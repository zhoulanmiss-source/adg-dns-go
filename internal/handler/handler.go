package doh

import (
    "bufio"
    "encoding/base64"
    "io"
    "net"
    "net/http"
    "net/url"
    "strings"
    "sync"
    "time"
    "adg-dns-go/rule"
)
var upstreams = []string{
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/dns-query",
}

var client = &http.Client{
    Timeout: 5 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns:        200,
        MaxIdleConnsPerHost: 100,
        IdleConnTimeout:     90 * time.Second,
        DisableCompression:  true,
        DialContext: (&net.Dialer{
            Timeout:   3 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,
    },
}

var (
    allowlist       = make(map[string]struct{})
    blocklist       = make(map[string]struct{})
    allowExceptions = make(map[string]struct{})
)

var once sync.Once

func Router() http.Handler {
    once.Do(func() {
        loadRules()
    })

    mux := http.NewServeMux()
    mux.HandleFunc("/430624", dohHandler)
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("hello world"))
    })
    return mux
}

func loadRules() {
    loadRuleFile("allowlists.txt", true)
    loadRuleFile("blocklists.txt", false)
}

func loadRuleFile(name string, isAllow bool) {
    data, err := rule.FS.ReadFile(name)
    if err != nil {
        println("read embed rule failed:", name, err.Error())
        return
    }

    scanner := bufio.NewScanner(strings.NewReader(string(data)))
    for scanner.Scan() {
        domain, isException := parseRule(scanner.Text())
        if domain == "" {
            continue
        }

        if isAllow {
            allowlist[domain] = struct{}{}
            allowExceptions[domain] = struct{}{}
        } else {
            if isException {
                allowExceptions[domain] = struct{}{}
            } else {
                blocklist[domain] = struct{}{}
            }
        }
    }
}

func parseRule(line string) (string, bool) {
    s := strings.TrimSpace(line)
    if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "!") {
        return "", false
    }

    isException := false
    if strings.HasPrefix(s, "@@") {
        isException = true
        s = strings.TrimPrefix(s, "@@")
    }

    if i := strings.Index(s, "$"); i != -1 {
        s = s[:i]
    }

    if strings.HasPrefix(s, "||") {
        s = s[2:]
    }

    if strings.Contains(s, "://") {
        u, err := url.Parse(s)
        if err == nil {
            s = u.Hostname()
        }
    }

    for _, sep := range []string{"^", "/", "?", "#"} {
        if i := strings.Index(s, sep); i != -1 {
            s = s[:i]
        }
    }

    s = strings.TrimPrefix(s, "*.")
    s = strings.TrimPrefix(s, ".")
    s = strings.ToLower(strings.TrimSpace(s))

    if strings.Count(s, ".") < 1 {
        return "", false
    }

    return s, isException
}

func domainMatch(domain string, rules map[string]struct{}) bool {
    d := domain
    for {
        if _, ok := rules[d]; ok {
            return true
        }
        i := strings.Index(d, ".")
        if i < 0 {
            return false
        }
        d = d[i+1:]
    }
}

func extractDomain(query []byte) string {
    i := 12
    var labels []string

    for {
        l := int(query[i])
        i++
        if l == 0 {
            break
        }
        labels = append(labels, string(query[i:i+l]))
        i += l
    }
    return strings.ToLower(strings.Join(labels, "."))
}

func buildNXDOMAIN(query []byte) []byte {
    txid := query[:2]
    flags := []byte{0x81, 0x83}
    header := append(txid, flags...)
    header = append(header, query[4:6]...)
    header = append(header, 0, 0, 0, 0, 0, 0)
    return append(header, query[12:]...)
}

type cacheItem struct {
    data      []byte
    expiresAt time.Time
}

var cache sync.Map

func dohHandler(w http.ResponseWriter, r *http.Request) {

    dnsParam := r.URL.Query().Get("dns")
    if dnsParam == "" {
        http.Error(w, "missing dns param", 400)
        return
    }

    query, err := base64.RawURLEncoding.DecodeString(dnsParam)
    if err != nil {
        http.Error(w, "invalid dns", 400)
        return
    }

    domain := extractDomain(query)

    // 黑名单逻辑
    if !domainMatch(domain, allowExceptions) && domainMatch(domain, blocklist) {
        w.Header().Set("Content-Type", "application/dns-message")
        w.Write(buildNXDOMAIN(query))
        return
    }

    key := string(query[2:])

    if v, ok := cache.Load(key); ok {
        item := v.(cacheItem)
        if time.Now().Before(item.expiresAt) {
            resp := append(query[:2], item.data[2:]...)
            w.Header().Set("Content-Type", "application/dns-message")
            w.Write(resp)
            return
        }
        cache.Delete(key)
    }

    var body []byte
    for _, upstream := range upstreams {
        reqURL := upstream + "?dns=" + url.QueryEscape(dnsParam)
        req, _ := http.NewRequest("GET", reqURL, nil)
        req.Header.Set("Accept", "application/dns-message")

        resp, err := client.Do(req)
        if err != nil {
            continue
        }

        body, err = io.ReadAll(resp.Body)
        resp.Body.Close()

        if err == nil && resp.StatusCode == 200 {
            break
        }
    }

    if body == nil {
        http.Error(w, "upstream failed", 502)
        return
    }

    cache.Store(key, cacheItem{
        data:      body,
        expiresAt: time.Now().Add(14400 * time.Second),
    })

    w.Header().Set("Content-Type", "application/dns-message")
    w.Write(body)
}
