package doh

import (
    "bufio"
    "encoding/base64"
    "encoding/binary"
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
    // "https://dns.alidns.com/dns-query",
    // "https://doh.pub/dns-query",
    // "https://doh.360.cn/dns-query",
    "https://el3iud.i996.me/430624",
    "https://adg.430624.xyz/430624",
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

// appendECS 直接在 query 末尾追加带 ECS 的 OPT RR，ARCOUNT+1
func appendECS(query []byte) []byte {
    ip := net.ParseIP("183.194.152.43").To4()

    // ECS Option (RFC 7871)
    // Option Code: 8
    // Option Len:  7 (family 2 + source 1 + scope 1 + addr 3)
    // Family:      1 (IPv4)
    // Source:      24
    // Scope:       0
    // Address:     前3字节 (183.194.152)
    ecsOption := []byte{
        0x00, 0x08, // option code = 8 (ECS)
        0x00, 0x07, // option length = 7
        0x00, 0x01, // family = 1 (IPv4)
        24,         // source prefix-length
        0,          // scope prefix-length
        ip[0], ip[1], ip[2], // 截断到 /24
    }

    // OPT RR
    // NAME:     0x00 (root)
    // TYPE:     41
    // CLASS:    4096 (UDP payload size)
    // TTL:      0 (extended rcode + flags)
    // RDLENGTH: len(ecsOption)
    optRR := make([]byte, 11+len(ecsOption))
    optRR[0] = 0x00                                                    // root name
    binary.BigEndian.PutUint16(optRR[1:3], 41)                        // type OPT
    binary.BigEndian.PutUint16(optRR[3:5], 4096)                      // UDP payload size
    binary.BigEndian.PutUint32(optRR[5:9], 0)                         // extended rcode + flags
    binary.BigEndian.PutUint16(optRR[9:11], uint16(len(ecsOption)))   // RDLENGTH
    copy(optRR[11:], ecsOption)

    // 拼接：原始 query + OPT RR，ARCOUNT+1
    result := make([]byte, len(query)+len(optRR))
    copy(result, query)
    arcount := binary.BigEndian.Uint16(result[10:12])
    binary.BigEndian.PutUint16(result[10:12], arcount+1)
    copy(result[len(query):], optRR)

    return result
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

    // 固定追加 ECS，重新编码
    ecsQuery := appendECS(query)
    ecsDnsParam := base64.RawURLEncoding.EncodeToString(ecsQuery)

    var body []byte
    for _, upstream := range upstreams {
        reqURL := upstream + "?dns=" + url.QueryEscape(ecsDnsParam)
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
        body = nil
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
