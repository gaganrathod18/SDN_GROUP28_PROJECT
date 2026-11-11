#include "ui_components/help_tab.h"
#include "ui_components/common.h"

namespace PacMan {
namespace UI {

using namespace ftxui;

Element helpPanel() {
    auto sec = [](const std::string& title) {
        return text(" [ " + title + " ]") | bold | color(Color::BlueLight);
    };
    auto kv = [](const std::string& key, const std::string& val) {
        return hbox({
            text(" " + key) | size(WIDTH, EQUAL, 20) | bold | color(Color::Yellow),
            text(val)       | color(Color::GrayLight) | flex,
        });
    };
    auto badge = [](const std::string& label, Color col, const std::string& desc) {
        return hbox({
            text(" " + label) | size(WIDTH, EQUAL, 9) | bold | color(col),
            text(desc)        | color(Color::GrayLight) | flex,
        });
    };

    // ── LEFT COLUMN ──────────────────────────────────────────────────────────
    auto left_col = vbox({
        text("  PacMan — Packet Analysis & Cyber Monitor") | bold | color(Color::GreenLight),
        text("  Real-time packet capture & security dashboard") | color(Color::GrayLight),
        separatorLight(),
        sec("Keybindings"),
        kv("Q / Esc",        "Quit PacMan"),
        kv("<- / ->",        "Navigate tabs"),
        kv("^ k  (Flows)",   "Scroll up"),
        kv("v j  (Flows)",   "Scroll down"),
        separatorLight(),
        sec("Tab Guide"),
        kv("0  Overview",  "BW sparkline, alerts, flows"),
        kv("1  Flows",     "Full live connection table"),
        kv("2  Alerts",    "Dedicated security alert feed"),
        kv("3  DNS",       "DNS/SNI query log"),
        kv("4  Protocols", "Traffic class breakdown"),
        kv("5  Endpoints", "Per-IP connection matrix"),
        kv("6  Traffic",   "300s BW/PPS sparklines"),
        kv("7  Analytics", "Top domains & talkers"),
        kv("8  Firewall",  "Live iptables drop matrix"),
        kv("9  IPS",       "Intrusion prevention actions"),
        kv("10 IDS",       "Deep packet inspection"),
        kv("11 Crypto",    "TLS ciphers & JA3 fingerprints"),
        kv("12 Help",      "This screen"),
        separatorLight(),
        sec("Alert Severity"),
        badge("LOW",    Color::GreenLight, "Informational — low risk"),
        badge("MEDIUM", Color::Yellow,     "Suspicious activity"),
        badge("HIGH",   Color::Red,        "Malicious — bell rings"),
    }) | flex;

    // ── RIGHT COLUMN ─────────────────────────────────────────────────────────
    auto right_col = vbox({
        sec("Flow Table Columns"),
        kv("SRC / DST IP", "Source and destination address"),
        kv("SPORT/DPORT",  "Source / destination port (orange)"),
        kv("PROTO",        "TCP / UDP / OTH"),
        kv("STATE",        "ESTAB | SYN | FIN | RST | CLOSE"),
        kv("CLASS",        "Traffic class (Streaming, DNS...)"),
        kv("DUR",          "Session duration since first packet"),
        kv("BYTES",        "Total bytes in flow"),
        kv("HOSTNAME",     "SNI / HTTP Host / DNS name"),
        separatorLight(),
        sec("Detection Rules"),
        kv("HIGH_CONN",   "> threshold conns from same src"),
        kv("PORT_SCAN",   "Source hit 10+ unique ports"),
        kv("UNKNOWN_DOM", "Unclassified domain first seen"),
        kv("LARGE_TX",    "Transfer exceeded byte limit"),
        kv("VIRUSTOTAL",  "Flagged malicious via VT API"),
        separatorLight(),
        sec("Config  (config/pacman.conf)"),
        kv("interface_name", "NIC to capture  (e.g. eth0)"),
        kv("refresh_ms",     "Dashboard refresh interval (ms)"),
        kv("log_file",       "Path to event log output"),
        kv("reports_dir",    "HTML/CSV report directory"),
        kv("vt_api_key",     "VirusTotal API key"),
        separatorLight(),
        sec("Build Info"),
        kv("Version",  "PacMan v1.0  —  FTXUI Dashboard"),
        kv("Capture",  "libpcap live & pcap file replay"),
        kv("Package",  "pacman-monitor-1.0-Linux.deb"),
        kv("Blocking", "sudo required for iptables hooks"),
    }) | flex;

    return hbox({
        left_col  | border | flex,
        right_col | border | flex,
    }) | flex;
}

}
}
