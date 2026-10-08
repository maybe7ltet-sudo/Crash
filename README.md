# Crash

Tool TLS flood terdistribusi via HTTP proxy rotation. Built in Go.
Single binary, no runtime, dobel klik langsung jalan.

---

## Fitur

- **Multi-vector TLS flood** — ClientHello chaos, malformed record injection, renegotiation flood.
- **Proxy rotation** — dukung 3000+ proxy, auto-mark dead, auto-reset kalau semua mati.
- **Auto proxy parse** — dukung format `ip:port`, `user:pass@ip:port`, `ip:port:user:pass`, `scheme://ip:port`.
- **Multi-auth** — HTTP Basic proxy auth via `Proxy-Authorization` header.
- **Live stats** — conns, pps, errors, bytes, proxy dead realtime.
- **Single binary** — compile sekali, jalan di mana aja. Nggak butuh Python, nggak butuh runtime apapun.

---

## Disclaimer

Tool ini dibuat untuk keperluan riset keamanan, stress-testing infrastruktur pribadi, dan pembelajaran protokol TLS. Penggunaan terhadap sistem tanpa izin eksplisit dari pemilik adalah ilegal di banyak yurisdiksi. Penulis tidak bertanggung jawab atas penyalahgunaan.

---

## Requirement

### Build dari source

- Go 1.21 atau lebih baru — [download](https://go.dev/dl/)
- Git

### Runtime

- Windows 10/11 (64-bit), Linux (x86_64), atau macOS (10.15+)
- Nggak butuh runtime tambahan

---

## Build

### Windows

```cmd
git clone https://github.com/<username>/Crash.git
cd Crash
go mod tidy
go build -ldflags "-s -w -H windowsgui" -o crash.exe .
