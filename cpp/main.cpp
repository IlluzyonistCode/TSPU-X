/**
 * TSPU X — C++ packet analysis / proxy component
 *
 * Two operation modes (select with --mode):
 *   sniffer  — libpcap passive capture (default, for testing)
 *   proxy    — transparent SOCKS5/HTTP proxy, accepts connections from XRAY
 *
 * Command port 4041: receives block/unblock/throttle/unthrottle commands from Elixir
 * Health port  4042: simple TCP health-check responder
 *
 * Logging: structured JSON to stdout via spdlog.
 */

#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <csignal>
#include <cstring>
#include <functional>
#include <vector>
#include <algorithm>

// POSIX / Linux
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

// libpcap (sniffer mode)
#include <pcap.h>

// spdlog — structured JSON logging
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/fmt/ostr.h>

#include "dns_parser.hpp"
#include "tls_parser.hpp"

// ─────────────────────────────────────────────
// Global logger (JSON-formatted stdout)
// ─────────────────────────────────────────────

std::shared_ptr<spdlog::logger> g_log;

void init_logger(const std::string& component = "sniffer") {
    // spdlog pattern that emits JSON lines
    auto sink = std::make_shared<spdlog::sinks::stdout_sink_mt>();
    sink->set_pattern(R"({"ts":"%Y-%m-%dT%H:%M:%S.%e","level":"%l","component":")" +
                      component + R"(","msg":"%v"})");
    g_log = std::make_shared<spdlog::logger>("tspu", sink);
    g_log->set_level(spdlog::level::info);
    spdlog::register_logger(g_log);
}

// ─────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────

enum class Mode { Sniffer, Proxy };

struct Config {
    Mode        mode             = Mode::Sniffer;
    std::string capture_iface   = "any";
    std::string pcap_file;                        // read from file instead of live capture
    std::string elixir_host     = "127.0.0.1";
    int         elixir_port     = 4040;
    int         cmd_port        = 4041;           // command listener
    int         health_port     = 4042;           // health check
    int         proxy_port      = 8888;           // SOCKS5 proxy listen port (proxy mode)
    bool        verbose         = false;
    // cleanup interval for expired entries
    int         cleanup_interval_s = 10;
    // Upstream SOCKS5 proxy (optional). If upstream_socks5_host is non-empty,
    // all outbound connections are tunnelled through it.
    std::string upstream_socks5_host;
    int         upstream_socks5_port = 11111;
};

Config g_cfg;

// ─────────────────────────────────────────────
// Block table  — key = "ip:domain"
// ─────────────────────────────────────────────

struct BlockEntry {
    int64_t until_ts;   // 0 = permanent; otherwise Unix epoch seconds
};

std::mutex                                     g_block_mu;
std::unordered_map<std::string, BlockEntry>    g_block_table;

// Throttle table — key = "ip:domain"
struct ThrottleEntry {
    int         delay_ms;
    int64_t     until_ts;   // 0 = permanent
};

std::mutex                                      g_throttle_mu;
std::unordered_map<std::string, ThrottleEntry>  g_throttle_table;

static int64_t now_ts() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool is_blocked(const std::string& ip, const std::string& domain) {
    std::lock_guard<std::mutex> lk(g_block_mu);
    auto key = ip + ':' + domain;
    auto it = g_block_table.find(key);
    if (it == g_block_table.end()) return false;
    if (it->second.until_ts == 0) return true;
    if (now_ts() >= it->second.until_ts) {
        g_block_table.erase(it);
        return false;
    }
    return true;
}

// Returns delay in ms (0 = no throttle)
int get_throttle_ms(const std::string& ip, const std::string& domain) {
    std::lock_guard<std::mutex> lk(g_throttle_mu);
    auto key = ip + ':' + domain;
    auto it = g_throttle_table.find(key);
    if (it == g_throttle_table.end()) return 0;
    if (it->second.until_ts != 0 && now_ts() >= it->second.until_ts) {
        g_throttle_table.erase(it);
        return 0;
    }
    return it->second.delay_ms;
}

void add_block(const std::string& ip, const std::string& domain, int64_t until) {
    std::lock_guard<std::mutex> lk(g_block_mu);
    g_block_table[ip + ':' + domain] = {until};
    g_log->info(R"({{"event":"block_added","ip":"{}","domain":"{}","until":{}}})", ip, domain, until);
}

void remove_block(const std::string& ip, const std::string& domain) {
    std::lock_guard<std::mutex> lk(g_block_mu);

    // Wildcard: if domain starts with "*." remove all matching entries
    if (domain.size() > 2 && domain[0] == '*' && domain[1] == '.') {
        std::string suffix = domain.substr(1); // ".deepseek.com"
        std::string prefix = ip + ':';
        std::vector<std::string> to_erase;
        for (auto& kv : g_block_table) {
            if (kv.first.substr(0, prefix.size()) == prefix) {
                std::string blocked_domain = kv.first.substr(prefix.size());
                // Match if domain ends with suffix or equals suffix without leading dot
                if (blocked_domain.size() >= suffix.size() &&
                    blocked_domain.compare(blocked_domain.size() - suffix.size(),
                                           suffix.size(), suffix) == 0) {
                    to_erase.push_back(kv.first);
                }
            }
        }
        for (auto& k : to_erase) {
            g_block_table.erase(k);
            g_log->info(R"({{"event":"block_removed","ip":"{}","domain":"{}"}})", ip, k.substr(prefix.size()));
        }
        return;
    }

    // Exact match
    g_block_table.erase(ip + ':' + domain);
    g_log->info(R"({{"event":"block_removed","ip":"{}","domain":"{}"}})", ip, domain);
}

void add_throttle(const std::string& ip, const std::string& domain, int delay_ms, int64_t until) {
    std::lock_guard<std::mutex> lk(g_throttle_mu);
    g_throttle_table[ip + ':' + domain] = {delay_ms, until};
    g_log->info(R"({{"event":"throttle_added","ip":"{}","domain":"{}","delay_ms":{},"until":{}}})",
                ip, domain, delay_ms, until);
}

void remove_throttle(const std::string& ip, const std::string& domain) {
    std::lock_guard<std::mutex> lk(g_throttle_mu);

    if (domain.size() > 2 && domain[0] == '*' && domain[1] == '.') {
        std::string suffix = domain.substr(1);
        std::string prefix = ip + ':';
        std::vector<std::string> to_erase;
        for (auto& kv : g_throttle_table) {
            if (kv.first.substr(0, prefix.size()) == prefix) {
                std::string d = kv.first.substr(prefix.size());
                if (d.size() >= suffix.size() &&
                    d.compare(d.size() - suffix.size(), suffix.size(), suffix) == 0) {
                    to_erase.push_back(kv.first);
                }
            }
        }
        for (auto& k : to_erase) g_throttle_table.erase(k);
        return;
    }

    g_throttle_table.erase(ip + ':' + domain);
}

// Periodic cleanup of expired entries
void cleanup_expired() {
    {
        std::lock_guard<std::mutex> lk(g_block_mu);
        int64_t ts = now_ts();
        for (auto it = g_block_table.begin(); it != g_block_table.end();) {
            if (it->second.until_ts != 0 && ts >= it->second.until_ts)
                it = g_block_table.erase(it);
            else
                ++it;
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_throttle_mu);
        int64_t ts = now_ts();
        for (auto it = g_throttle_table.begin(); it != g_throttle_table.end();) {
            if (it->second.until_ts != 0 && ts >= it->second.until_ts)
                it = g_throttle_table.erase(it);
            else
                ++it;
        }
    }
}

// ─────────────────────────────────────────────
// Stats for /health and /metrics
// ─────────────────────────────────────────────

std::atomic<uint64_t> g_events_total{0};
std::atomic<uint64_t> g_events_last_min{0};
std::atomic<uint64_t> g_events_window{0};  // rolling 60s

// ─────────────────────────────────────────────
// Elixir event sender (newline-delimited JSON, TCP)
// ─────────────────────────────────────────────

int         g_elixir_sock = -1;
std::mutex  g_send_mu;

bool connect_elixir() {
    // Use getaddrinfo so hostnames like "elixir" (Docker DNS) resolve correctly
    struct addrinfo hints{}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(g_cfg.elixir_port);
    if (getaddrinfo(g_cfg.elixir_host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        g_log->warn("connect_elixir: DNS resolution failed for {}", g_cfg.elixir_host);
        return false;
    }
    g_elixir_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_elixir_sock < 0) { freeaddrinfo(res); return false; }
    if (connect(g_elixir_sock, res->ai_addr, res->ai_addrlen) < 0) {
        g_log->warn("connect_elixir: connect failed: {}", strerror(errno));
        close(g_elixir_sock); g_elixir_sock = -1;
        freeaddrinfo(res); return false;
    }
    freeaddrinfo(res);
    g_log->info("connect_elixir: connected to {}:{}", g_cfg.elixir_host, g_cfg.elixir_port);
    return true;
}

void send_event(const std::string& ip, const std::string& domain,
                const std::string& type, int64_t ts) {
    if (g_elixir_sock < 0) return;
    std::ostringstream ss;
    ss << "{\"ip\":\"" << ip << "\",\"domain\":\"" << domain
       << "\",\"type\":\"" << type << "\",\"ts\":" << ts << "}\n";
    std::string msg = ss.str();
    std::lock_guard<std::mutex> lk(g_send_mu);
    if (send(g_elixir_sock, msg.c_str(), msg.size(), MSG_NOSIGNAL) < 0) {
        close(g_elixir_sock); g_elixir_sock = -1;
    }
    g_events_total++;
    g_events_window++;
}

// ─────────────────────────────────────────────
// Shared: process a captured/observed domain event
// ─────────────────────────────────────────────

void handle_domain_event(const std::string& client_ip, const std::string& domain,
                         const std::string& type, int64_t ts) {
    if (g_cfg.verbose)
        g_log->info(R"({{"event":"{}","ip":"{}","domain":"{}"}})", type, client_ip, domain);

    int delay_ms = get_throttle_ms(client_ip, domain);
    if (delay_ms > 0) {
        struct timespec ts_sleep = {delay_ms / 1000, (delay_ms % 1000) * 1000000L};
        nanosleep(&ts_sleep, nullptr);
    }

    if (!is_blocked(client_ip, domain)) {
        send_event(client_ip, domain, type, ts);
    }
}

// ─────────────────────────────────────────────
// Command listener (port 4041)
// Parses: {"cmd":"block","ip":"...","domain":"...","until":0,"duration_seconds":0}
//         {"cmd":"unblock","ip":"...","domain":"..."}
//         {"cmd":"throttle","ip":"...","domain":"...","delay_ms":2000,"duration_seconds":3600}
//         {"cmd":"unthrottle","ip":"...","domain":"..."}
// ─────────────────────────────────────────────

std::atomic<bool> g_running{true};

// Minimal JSON field extractor (avoids heavy deps)
// Finds "key":"value" and returns value string
static std::string json_str(const std::string& buf, const std::string& key) {
    // Search for "key" followed by ":"
    std::string search = '"' + key + '"';
    auto kp = buf.find(search);
    if (kp == std::string::npos) return "";
    // Find the colon after the key
    auto cp = buf.find(':', kp + search.size());
    if (cp == std::string::npos) return "";
    // Find opening quote of value
    auto vp = buf.find('"', cp + 1);
    if (vp == std::string::npos) return "";
    // Find closing quote of value
    auto ep = buf.find('"', vp + 1);
    if (ep == std::string::npos) return "";
    return buf.substr(vp + 1, ep - vp - 1);
}

static int64_t json_int(const std::string& buf, const std::string& key, int64_t def = 0) {
    std::string search = '"' + key + '"';
    auto kp = buf.find(search);
    if (kp == std::string::npos) return def;
    auto cp = buf.find(':', kp + search.size());
    if (cp == std::string::npos) return def;
    try { return std::stoll(buf.substr(cp + 1)); } catch (...) { return def; }
}

static void handle_command(const std::string& line) {
    std::string cmd    = json_str(line, "cmd");
    std::string ip     = json_str(line, "ip");
    std::string domain = json_str(line, "domain");

    if (cmd == "block") {
        int64_t until    = json_int(line, "until", 0);
        int64_t dur      = json_int(line, "duration_seconds", 0);
        // duration_seconds takes precedence over absolute until
        if (dur > 0) until = now_ts() + dur;
        if (!ip.empty() && !domain.empty()) add_block(ip, domain, until);

    } else if (cmd == "unblock") {
        if (!ip.empty() && !domain.empty()) remove_block(ip, domain);

    } else if (cmd == "throttle") {
        int     delay_ms = static_cast<int>(json_int(line, "delay_ms", 500));
        int64_t dur      = json_int(line, "duration_seconds", 0);
        int64_t until    = dur > 0 ? now_ts() + dur : 0;
        if (!ip.empty() && !domain.empty()) add_throttle(ip, domain, delay_ms, until);

    } else if (cmd == "unthrottle") {
        if (!ip.empty() && !domain.empty()) remove_throttle(ip, domain);
    }
}

void command_listener_thread() {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(static_cast<uint16_t>(g_cfg.cmd_port));
    if (bind(srv, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
        g_log->error("Cannot bind command port {}", g_cfg.cmd_port);
        return;
    }
    listen(srv, 4);
    g_log->info("Command listener on port {}", g_cfg.cmd_port);

    while (g_running) {
        sockaddr_in ca{}; socklen_t cl = sizeof(ca);
        int cfd = accept(srv, reinterpret_cast<sockaddr*>(&ca), &cl);
        if (cfd < 0) continue;
        std::string buf;
        char ch;
        while (recv(cfd, &ch, 1, 0) == 1) {
            if (ch == '\n') { handle_command(buf); buf.clear(); }
            else buf += ch;
        }
        close(cfd);
    }
    close(srv);
}

// ─────────────────────────────────────────────
// Health check listener (port 4042)
// On connect: sends one-line JSON and closes
// ─────────────────────────────────────────────

void health_listener_thread() {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(static_cast<uint16_t>(g_cfg.health_port));
    if (bind(srv, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
        g_log->error("Cannot bind health port {}", g_cfg.health_port);
        return;
    }
    listen(srv, 8);

    while (g_running) {
        sockaddr_in ca{}; socklen_t cl = sizeof(ca);
        int cfd = accept(srv, reinterpret_cast<sockaddr*>(&ca), &cl);
        if (cfd < 0) continue;

        size_t nblocks, nthrottle;
        {
            std::lock_guard<std::mutex> lk(g_block_mu);
            nblocks = g_block_table.size();
        }
        {
            std::lock_guard<std::mutex> lk(g_throttle_mu);
            nthrottle = g_throttle_table.size();
        }

        // Minimal HTTP 200 response so curl works
        std::ostringstream body;
        body << "{\"status\":\"ok\",\"mode\":\""
             << (g_cfg.mode == Mode::Proxy ? "proxy" : "sniffer")
             << "\",\"active_blocks\":" << nblocks
             << ",\"active_throttles\":" << nthrottle
             << ",\"events_total\":" << g_events_total.load()
             << ",\"events_last_min\":" << g_events_last_min.load()
             << "}";
        std::string b = body.str();
        std::string resp =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            "Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b;
        send(cfd, resp.c_str(), resp.size(), MSG_NOSIGNAL);
        close(cfd);
    }
    close(srv);
}

// ─────────────────────────────────────────────
// Cleanup + stats reset thread
// ─────────────────────────────────────────────

void maintenance_thread() {
    int ticks = 0;
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(g_cfg.cleanup_interval_s));
        cleanup_expired();
        ticks++;
        // Every 60s update last-minute counter
        if (ticks * g_cfg.cleanup_interval_s >= 60) {
            g_events_last_min = g_events_window.exchange(0);
            ticks = 0;
        }
    }
}

// ─────────────────────────────────────────────
// MODE A: sniffer (libpcap)
// ─────────────────────────────────────────────

static void pcap_packet_handler(uint8_t*, const pcap_pkthdr* hdr, const uint8_t* pkt) {
    if (hdr->caplen < 14) return;
    const uint8_t* ip_start = pkt + 14;
    size_t ip_len = hdr->caplen - 14;
    if (ip_len < 20) return;
    if ((ip_start[0] >> 4) != 4) return;

    uint8_t  ihl      = (ip_start[0] & 0x0F) * 4;
    uint8_t  proto    = ip_start[9];
    uint32_t src_raw  = *reinterpret_cast<const uint32_t*>(ip_start + 12);
    char src_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_raw, src_buf, sizeof(src_buf));
    std::string client_ip(src_buf);
    int64_t ts = static_cast<int64_t>(hdr->ts.tv_sec);

    const uint8_t* transport = ip_start + ihl;
    size_t         tlen      = ip_len - ihl;

    if (proto == IPPROTO_UDP && tlen >= 8) {
        uint16_t dport = ntohs(*reinterpret_cast<const uint16_t*>(transport + 2));
        uint16_t sport = ntohs(*reinterpret_cast<const uint16_t*>(transport));
        if (dport == 53 || sport == 53) {
            std::string dom = dns::extract_query_domain(transport + 8, tlen - 8);
            if (!dom.empty()) handle_domain_event(client_ip, dom, "dns", ts);
        }
    } else if (proto == IPPROTO_TCP && tlen >= 20) {
        uint16_t dport = ntohs(*reinterpret_cast<const uint16_t*>(transport + 2));
        uint8_t  doff  = (transport[12] >> 4) * 4;
        if (doff > tlen) return;
        const uint8_t* payload = transport + doff;
        size_t         plen    = tlen - doff;
        if (dport == 443 && plen > 0) {
            std::string sni = tls::extract_sni(payload, plen);
            if (!sni.empty()) handle_domain_event(client_ip, sni, "sni", ts);
        }
    }
}

void run_sniffer() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;

    if (!g_cfg.pcap_file.empty()) {
        g_log->info("Opening pcap file: {}", g_cfg.pcap_file);
        handle = pcap_open_offline(g_cfg.pcap_file.c_str(), errbuf);
    } else {
        g_log->info("Capturing on interface: {}", g_cfg.capture_iface);
        handle = pcap_open_live(g_cfg.capture_iface.c_str(), 65535, 1, 100, errbuf);
    }

    if (!handle) {
        g_log->error("pcap error: {}", errbuf);
        std::exit(1);
    }

    struct bpf_program fp{};
    const char* filt = "udp port 53 or tcp port 443";
    if (pcap_compile(handle, &fp, filt, 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    }

    g_log->info("Sniffer running");
    while (g_running) {
        int rc = pcap_dispatch(handle, 100,
            reinterpret_cast<pcap_handler>(pcap_packet_handler), nullptr);
        if (rc == -1) { g_log->error("pcap dispatch error: {}", pcap_geterr(handle)); break; }
        if (rc == -2) break;
        if (g_elixir_sock < 0) connect_elixir();
    }
    pcap_close(handle);
}

// ─────────────────────────────────────────────
// MODE B: SOCKS5 transparent proxy
// Accepts from XRAY, relays to destination, extracts SNI/Host
// ─────────────────────────────────────────────

// Forward all data between two sockets until one closes
// Relay data between two fds until both sides close.
// Handles half-close (FIN from one side) correctly:
// when src reaches EOF we shut down the write side of dst so it also terminates gracefully.
static void relay(int a, int b) {
    fd_set fds;
    char buf[16384];
    bool a_open = true, b_open = true;

    // Idle timeout: kill connection if no data flows for 120s
    const int IDLE_TIMEOUT_S = 120;

    while (a_open || b_open) {
        FD_ZERO(&fds);
        if (a_open) FD_SET(a, &fds);
        if (b_open) FD_SET(b, &fds);
        int max_fd = std::max(a, b) + 1;
        struct timeval tv{IDLE_TIMEOUT_S, 0};
        int rc = select(max_fd, &fds, nullptr, nullptr, &tv);
        if (rc == 0) break;  // idle timeout
        if (rc < 0) break;   // error

        // a → b
        if (a_open && FD_ISSET(a, &fds)) {
            ssize_t n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0) {
                // a sent FIN — propagate to b
                shutdown(b, SHUT_WR);
                a_open = false;
            } else {
                ssize_t sent = 0;
                while (sent < n) {
                    ssize_t w = send(b, buf + sent, n - sent, MSG_NOSIGNAL);
                    if (w <= 0) { a_open = b_open = false; break; }
                    sent += w;
                }
            }
        }
        // b → a
        if (b_open && FD_ISSET(b, &fds)) {
            ssize_t n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0) {
                shutdown(a, SHUT_WR);
                b_open = false;
            } else {
                ssize_t sent = 0;
                while (sent < n) {
                    ssize_t w = send(a, buf + sent, n - sent, MSG_NOSIGNAL);
                    if (w <= 0) { a_open = b_open = false; break; }
                    sent += w;
                }
            }
        }
    }
}

// Connect to remote host:port, return fd or -1
// If g_cfg.upstream_socks5_host is set, tunnels through that SOCKS5 proxy.
static int connect_remote(const std::string& host, uint16_t port) {
    struct timeval tv{5, 0};

    if (!g_cfg.upstream_socks5_host.empty()) {
        // ── Connect to upstream SOCKS5 ──────────────────────────────────────
        struct addrinfo hints{}, *res;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        std::string port_str = std::to_string(g_cfg.upstream_socks5_port);
        if (getaddrinfo(g_cfg.upstream_socks5_host.c_str(), port_str.c_str(), &hints, &res) != 0) return -1;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { freeaddrinfo(res); return -1; }
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
            close(fd); freeaddrinfo(res); return -1;
        }
        freeaddrinfo(res);

        // ── SOCKS5 greeting (no-auth) ────────────────────────────────────────
        uint8_t greeting[3] = {0x05, 0x01, 0x00};
        if (send(fd, greeting, 3, MSG_NOSIGNAL) != 3) { close(fd); return -1; }
        uint8_t srv_choice[2];
        if (recv(fd, srv_choice, 2, MSG_WAITALL) != 2 ||
            srv_choice[0] != 0x05 || srv_choice[1] != 0x00) {
            g_log->warn("upstream SOCKS5 rejected no-auth method");
            close(fd); return -1;
        }

        // ── SOCKS5 CONNECT request (domain name) ────────────────────────────
        uint8_t dlen = static_cast<uint8_t>(host.size());
        std::vector<uint8_t> req;
        req.reserve(7 + dlen);
        req.insert(req.end(), {0x05, 0x01, 0x00, 0x03, dlen});
        req.insert(req.end(), host.begin(), host.end());
        uint16_t port_be = htons(port);
        req.push_back(static_cast<uint8_t>(port_be >> 8));
        req.push_back(static_cast<uint8_t>(port_be & 0xFF));
        if (send(fd, req.data(), req.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(req.size())) {
            close(fd); return -1;
        }

        // ── SOCKS5 response ──────────────────────────────────────────────────
        uint8_t resp[10];
        ssize_t rn = recv(fd, resp, sizeof(resp), 0);
        if (rn < 10 || resp[0] != 0x05 || resp[1] != 0x00) {
            g_log->warn("upstream SOCKS5 CONNECT failed, rep={}", rn > 1 ? resp[1] : 0xFF);
            close(fd); return -1;
        }

        g_log->info("upstream SOCKS5 tunnel: {}:{} via {}:{}",
                    host, port,
                    g_cfg.upstream_socks5_host, g_cfg.upstream_socks5_port);
        return fd;
    }

    // ── Direct connect (no upstream proxy) ──────────────────────────────────
    struct addrinfo hints{}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return fd;
}

// Handle one SOCKS5 client connection from XRAY
static void handle_socks5_client(int cfd, const std::string& peer_ip) {
    uint8_t buf[512];

    // SOCKS5 greeting: VER(1) NMETHODS(1) METHODS(N)
    ssize_t n = recv(cfd, buf, sizeof(buf), 0);
    if (n < 2 || buf[0] != 0x05) { close(cfd); return; }
    // Accept: no auth required
    uint8_t reply2[2] = {0x05, 0x00};
    send(cfd, reply2, 2, MSG_NOSIGNAL);

    // SOCKS5 request: VER CMD RSV ATYP ...
    n = recv(cfd, buf, sizeof(buf), 0);
    if (n < 7 || buf[0] != 0x05) { close(cfd); return; }
    uint8_t cmd  = buf[1];
    uint8_t atyp = buf[3];

    std::string dest_host;
    uint16_t    dest_port = 0;

    if (atyp == 0x01) {                    // IPv4
        if (n < 10) { close(cfd); return; }
        char ip4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, buf + 4, ip4, sizeof(ip4));
        dest_host = ip4;
        dest_port = ntohs(*reinterpret_cast<uint16_t*>(buf + 8));
    } else if (atyp == 0x03) {             // domain
        uint8_t dlen = buf[4];
        if (n < 5 + dlen + 2) { close(cfd); return; }
        dest_host = std::string(reinterpret_cast<char*>(buf + 5), dlen);
        dest_port = ntohs(*reinterpret_cast<uint16_t*>(buf + 5 + dlen));
    } else {
        // IPv6 or unsupported — reject
        uint8_t err[10] = {0x05,0x08,0x00,0x01,0,0,0,0,0,0};
        send(cfd, err, sizeof(err), MSG_NOSIGNAL);
        close(cfd); return;
    }

    if (cmd != 0x01) {   // only CONNECT supported
        uint8_t err[10] = {0x05,0x07,0x00,0x01,0,0,0,0,0,0};
        send(cfd, err, sizeof(err), MSG_NOSIGNAL);
        close(cfd); return;
    }

    // Before connecting upstream: check block / throttle using dest_host as domain
    std::string observed_domain = dest_host;

    if (is_blocked(peer_ip, observed_domain)) {
        // Reject with SOCKS5 "Connection refused"
        g_log->info(R"({{"event":"proxy_blocked","ip":"{}","domain":"{}"}})", peer_ip, observed_domain);
        uint8_t err[10] = {0x05,0x05,0x00,0x01,0,0,0,0,0,0};
        send(cfd, err, sizeof(err), MSG_NOSIGNAL);
        close(cfd); return;
    }

    int delay_ms = get_throttle_ms(peer_ip, observed_domain);

    // Connect to remote
    int rfd = connect_remote(dest_host, dest_port);
    if (rfd < 0) {
        uint8_t err[10] = {0x05,0x04,0x00,0x01,0,0,0,0,0,0};
        send(cfd, err, sizeof(err), MSG_NOSIGNAL);
        close(cfd); return;
    }

    // SOCKS5 success reply
    uint8_t ok[10] = {0x05,0x00,0x00,0x01,0,0,0,0,0,0};
    send(cfd, ok, sizeof(ok), MSG_NOSIGNAL);

    // For HTTPS: peek at the first TLS ClientHello to extract SNI
    if (dest_port == 443) {
        uint8_t peek[4096];
        ssize_t pn = recv(cfd, peek, sizeof(peek), MSG_PEEK);
        if (pn > 0) {
            std::string sni = tls::extract_sni(peek, static_cast<size_t>(pn));
            if (!sni.empty()) observed_domain = sni;
        }
    }

    // Send event to Elixir
    handle_domain_event(peer_ip, observed_domain,
                        dest_port == 443 ? "sni" : "dns",
                        now_ts());

    // Apply throttle delay before relaying
    if (delay_ms > 0) {
        struct timespec ts_sleep = {delay_ms / 1000, (delay_ms % 1000) * 1000000L};
        nanosleep(&ts_sleep, nullptr);
    }

    // Relay data until connection closes
    relay(cfd, rfd);
    close(cfd);
    close(rfd);
}

void run_proxy() {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(static_cast<uint16_t>(g_cfg.proxy_port));
    if (bind(srv, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
        g_log->critical("Cannot bind proxy port {}", g_cfg.proxy_port);
        std::exit(1);
    }
    listen(srv, 128);
    g_log->info("SOCKS5 proxy listening on port {}", g_cfg.proxy_port);

    while (g_running) {
        sockaddr_in ca{}; socklen_t cl = sizeof(ca);
        int cfd = accept(srv, reinterpret_cast<sockaddr*>(&ca), &cl);
        if (cfd < 0) continue;
        char peer_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ca.sin_addr, peer_buf, sizeof(peer_buf));
        std::string peer_ip(peer_buf);
        // Each connection in its own thread (small number of VPN clients)
        std::thread([cfd, peer_ip]{ handle_socks5_client(cfd, peer_ip); }).detach();
    }
    close(srv);
}

// ─────────────────────────────────────────────
// Signal handler
// ─────────────────────────────────────────────

void sig_handler(int) { g_running = false; }

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

int main(int argc, char* argv[]) {
    init_logger("cpp_sniffer");

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if      (a == "--mode"         && i+1<argc) { std::string m=argv[++i]; g_cfg.mode = (m=="proxy")?Mode::Proxy:Mode::Sniffer; }
        else if (a == "--iface"        && i+1<argc) g_cfg.capture_iface  = argv[++i];
        else if (a == "--pcap"         && i+1<argc) g_cfg.pcap_file      = argv[++i];
        else if (a == "--elixir-host"  && i+1<argc) g_cfg.elixir_host    = argv[++i];
        else if (a == "--elixir-port"  && i+1<argc) g_cfg.elixir_port    = std::stoi(argv[++i]);
        else if (a == "--proxy-port"   && i+1<argc) g_cfg.proxy_port     = std::stoi(argv[++i]);
        else if (a == "--upstream-socks5"      && i+1<argc) g_cfg.upstream_socks5_host = argv[++i];
        else if (a == "--upstream-socks5-port" && i+1<argc) g_cfg.upstream_socks5_port = std::stoi(argv[++i]);
        else if (a == "--cmd-port"     && i+1<argc) g_cfg.cmd_port       = std::stoi(argv[++i]);
        else if (a == "--health-port"  && i+1<argc) g_cfg.health_port    = std::stoi(argv[++i]);
        else if (a == "--verbose" || a == "-v")      g_cfg.verbose        = true;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    // Environment variable overrides (lower priority than CLI flags)
    if (g_cfg.upstream_socks5_host.empty()) {
        const char* env_host = std::getenv("UPSTREAM_SOCKS5_HOST");
        if (env_host && env_host[0]) g_cfg.upstream_socks5_host = env_host;
    }
    if (const char* env_port = std::getenv("UPSTREAM_SOCKS5_PORT"))
        if (env_port[0]) g_cfg.upstream_socks5_port = std::stoi(env_port);

    g_log->info("Starting TSPU X sniffer, mode={}, elixir={}:{}",
                g_cfg.mode == Mode::Proxy ? "proxy" : "sniffer",
                g_cfg.elixir_host, g_cfg.elixir_port);

    connect_elixir();

    // Background threads
    std::thread(command_listener_thread).detach();
    std::thread(health_listener_thread).detach();
    std::thread(maintenance_thread).detach();

    if (g_cfg.mode == Mode::Proxy)
        run_proxy();
    else
        run_sniffer();

    g_log->info("Shutting down");
    if (g_elixir_sock >= 0) close(g_elixir_sock);
    return 0;
}