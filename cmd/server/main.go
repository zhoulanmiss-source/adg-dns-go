package main

import (
    "log"
    "net/http"
    "os"
    "time"

    "adg-dns-go/internal/handler"
)

func main() {

    port := os.Getenv("PORT")
    if port == "" {
        port = "3000"
    }

    server := &http.Server{
        Addr:              ":" + port,
        Handler:           doh.Router(), // ✅ 使用我们的 DoH 路由
        ReadTimeout:       5 * time.Second,
        WriteTimeout:      10 * time.Second,
        IdleTimeout:       120 * time.Second,
        ReadHeaderTimeout: 2 * time.Second,
    }

    log.Println("Go DoH server running on :" + port)
    log.Fatal(server.ListenAndServe())
}
