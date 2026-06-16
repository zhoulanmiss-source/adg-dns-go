package doh

import (
    "context"
    "encoding/base64"
    "encoding/binary"
    "io"
    "net"
    "net/http"
    "net/url"
    "sync"
    "time"
)

var upstreams = []string{
    // "https://dns.alidns.com/dns-query",
    // "https://doh.pub/dns-query",
    // "https://doh.360.cn/dns-query",
    "https://el3iud.i996.me/430624",
    "https://adg-lb.430624.xyz/430624",
    "https://adg.430624.xyz/430624",
}

// 缓存时间，可按需修改
var cacheTTL = 30 * time.Minute

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

func Router() http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("/430624", dohHandler)
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("hello world"))
    })
    return mux
}

// appendECS 直接在 query 末尾追加带 ECS 的 OPT RR，ARCOUNT+1
func appendECS(query []byte) []byte {
    ip := net.ParseIP("183.194.152.43").To4()
    ecsOption := []byte{
        0x00, 0x08, // option code = 8 (ECS)
        0x00, 0x07, // option length = 7
        0x00, 0x01, // family = 1 (IPv4)
        24,         // source prefix-length
        0,          // scope prefix-length
        ip[0], ip[1], ip[2], // 截断到 /24
    }
    optRR := make([]byte, 11+len(ecsOption))
    optRR[0] = 0x00                                                 // root name
    binary.BigEndian.PutUint16(optRR[1:3], 41)                     // type OPT
    binary.BigEndian.PutUint16(optRR[3:5], 4096)                   // UDP payload size
    binary.BigEndian.PutUint32(optRR[5:9], 0)                      // extended rcode + flags
    binary.BigEndian.PutUint16(optRR[9:11], uint16(len(ecsOption))) // RDLENGTH
    copy(optRR[11:], ecsOption)

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

// queryUpstreams 并发请求所有 upstream，返回最快的成功结果
func queryUpstreams(ecsDnsParam string) []byte {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    type result struct {
        body []byte
    }
    resultCh := make(chan result, len(upstreams))

    var wg sync.WaitGroup
    for _, upstream := range upstreams {
        wg.Add(1)
        go func(upstream string) {
            defer wg.Done()

            reqURL := upstream + "?dns=" + url.QueryEscape(ecsDnsParam)
            req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
            if err != nil {
                return
            }
            req.Header.Set("Accept", "application/dns-message")

            resp, err := client.Do(req)
            if err != nil {
                return
            }
            defer resp.Body.Close()

            if resp.StatusCode != 200 {
                return
            }
            body, err := io.ReadAll(resp.Body)
            if err != nil || body == nil {
                return
            }

            select {
            case resultCh <- result{body: body}:
            case <-ctx.Done():
            }
        }(upstream)
    }

    // 所有 goroutine 结束后关闭 channel（用于全部失败时退出）
    go func() {
        wg.Wait()
        close(resultCh)
    }()

    // 取第一个成功的结果
    if res, ok := <-resultCh; ok {
        cancel() // 取消其余请求
        return res.body
    }
    return nil
}

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

    // 缓存命中
    key := string(query[2:])
    if v, ok := cache.Load(key); ok {
        item := v.(cacheItem)
        if time.Now().Before(item.expiresAt) {
            resp := append(append([]byte{}, query[:2]...), item.data[2:]...)
            w.Header().Set("Content-Type", "application/dns-message")
            w.Write(resp)
            return
        }
        cache.Delete(key)
    }

    // 固定追加 ECS，重新编码
    ecsQuery := appendECS(query)
    ecsDnsParam := base64.RawURLEncoding.EncodeToString(ecsQuery)

    // 并发查询所有上游，取最快成功结果
    body := queryUpstreams(ecsDnsParam)
    if body == nil {
        http.Error(w, "upstream failed", 502)
        return
    }

    cache.Store(key, cacheItem{
        data:      body,
        expiresAt: time.Now().Add(cacheTTL),
    })

    w.Header().Set("Content-Type", "application/dns-message")
    w.Write(body)
}
