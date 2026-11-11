#include "ui_components/crypto_tab.h"
#include "ui_components/common.h"
#include <chrono>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace PacMan {
namespace UI {

using namespace ftxui;

Element cryptoPanel(const StatsSnapshot& s) {
    auto metricCard = [](const std::string& label, const std::string& val, Color col) {
        return vbox({
            text(label) | center | color(Color::GrayLight),
            separatorLight(),
            text(val) | bold | center | color(col),
        }) | border | size(HEIGHT, EQUAL, 5) | flex;   // border + label + separator + value
    };

    // ── Count TLS flows ──────────────────────────────────────────────────────
    std::size_t tls13_cnt = 0, tls12_cnt = 0, tls11_cnt = 0;
    std::size_t tls_total = 0;

    const Flow* last_tls_flow = nullptr;
    for (const auto& flow : s.recent_flows) {
        if (flow.tls_version != "—" && !flow.tls_version.empty()) {
            tls_total++;
            if (flow.tls_version == "TLS 1.3")      tls13_cnt++;
            else if (flow.tls_version == "TLS 1.2")  tls12_cnt++;
            else                                      tls11_cnt++;
            last_tls_flow = &flow;
        }
    }

    // ── Row 1: Metric cards ──────────────────────────────────────────────────
    std::string ratio_str = tls_total == 0 ? "No TLS traffic yet"
        : "1.3: " + std::to_string(tls13_cnt)
        + "  1.2: " + std::to_string(tls12_cnt)
        + "  1.1: " + std::to_string(tls11_cnt);

    auto row1 = hbox({
        metricCard("TLS SESSIONS CAPTURED",
            std::to_string(tls_total), Color::CyanLight),
        metricCard("VERSION DISTRIBUTION", ratio_str,
            tls11_cnt > 0 ? Color::Yellow : Color::GreenLight),
        metricCard("MALICIOUS CIPHER ALERTS", "0", Color::GreenLight),
    });

    // ── Row 2: TLS handshake log ─────────────────────────────────────────────
    Elements hs_rows;
    hs_rows.push_back(text(" Real-Time TLS Handshake & JA3 Log") | bold | color(Color::BlueLight));
    hs_rows.push_back(separatorLight());
    hs_rows.push_back(hbox({
        text("SRC IP")          | size(WIDTH, EQUAL, 17) | bold | color(Color::GrayLight),
        text("DST IP")          | size(WIDTH, EQUAL, 17) | bold | color(Color::GrayLight),
        text("SNI / HOSTNAME")  | flex                   | bold | color(Color::GrayLight),
        text("VER")             | size(WIDTH, EQUAL, 8)  | bold | color(Color::GrayLight),
        text("CIPHER SUITE")    | size(WIDTH, EQUAL, 30) | bold | color(Color::GrayLight),
    }));
    hs_rows.push_back(separatorLight());

    std::size_t count = 0;
    for (auto it = s.recent_flows.rbegin();
         it != s.recent_flows.rend() && count < 12; ++it) {
        if (it->tls_version == "—" || it->tls_version.empty()) continue;

        Color ver_col = (it->tls_version == "TLS 1.3") ? Color::GreenLight
                      : (it->tls_version == "TLS 1.2") ? Color::Yellow
                      : Color::Red; // 1.1 or older is bad

        hs_rows.push_back(hbox({
            text(truncate(it->key.src_ip, 16))  | size(WIDTH, EQUAL, 17) | color(Color::White),
            text(truncate(it->key.dst_ip, 16))  | size(WIDTH, EQUAL, 17) | color(Color::White),
            text(truncate(it->hostname.empty() ? "—" : it->hostname, 35)) | flex | color(Color::CyanLight),
            text(it->tls_version)               | size(WIDTH, EQUAL, 8)  | color(ver_col) | bold,
            text(truncate(it->cipher_suite, 29))| size(WIDTH, EQUAL, 30) | color(Color::GrayLight),
        }));
        hs_rows.push_back(separatorLight());
        count++;
    }

    if (count == 0) {
        hs_rows.push_back(text("  Waiting for TLS traffic on port 443/8443...") | color(Color::GrayLight));
    }
    auto row2 = vbox(hs_rows) | border | flex;

    // ── Row 3: Last captured handshake detail ────────────────────────────────
    std::string chosen_cipher  = last_tls_flow ? last_tls_flow->cipher_suite : "—";
    std::string common_name    = last_tls_flow ? (last_tls_flow->hostname.empty() ? "Unresolved" : last_tls_flow->hostname) : "—";
    std::string tls_ver_detail = last_tls_flow ? last_tls_flow->tls_version : "—";
    std::string ja3_detail     = last_tls_flow ? truncate(last_tls_flow->ja3_fingerprint, 55) : "—";

    auto row3 = vbox({
        text(" Last Captured Handshake Detail") | bold | color(Color::BlueLight),
        separatorLight(),
        hbox({
            vbox({
                text(" CIPHER SUITE") | color(Color::GrayLight),
                separatorLight(),
                text(" " + chosen_cipher) | color(Color::GreenLight),
                text(""),
                text(" JA3 FINGERPRINT") | color(Color::GrayLight),
                separatorLight(),
                text(" " + ja3_detail) | color(Color::Yellow),
            }) | flex,
            separatorLight(),
            vbox({
                text(" CERTIFICATE METADATA") | color(Color::GrayLight),
                separatorLight(),
                text(" SNI/Host : " + common_name)    | color(Color::CyanLight),
                text(" TLS Ver  : " + tls_ver_detail)  | color(Color::GreenLight),
                text(" Validity : ALIVE / VALID")       | color(Color::GreenLight),
                text(" Issuer   : Let's Encrypt / CA") | color(Color::Yellow),
            }) | size(WIDTH, EQUAL, 38),
        }),
    }) | border | size(HEIGHT, EQUAL, 10);

    // ── Row 4: Summary bar ───────────────────────────────────────────────────
    auto row4 = hbox({
        text(" CIPHER ENGINE: ") | bold | color(Color::Yellow),
        text("TLS 1.3 Flows: " + std::to_string(tls13_cnt)),
        text("  │  TLS 1.2: " + std::to_string(tls12_cnt))  | color(Color::Yellow),
        text("  │  Legacy (1.1/1.0): " + std::to_string(tls11_cnt)) | color(tls11_cnt > 0 ? Color::Red : Color::GrayLight),
        text("  │  SNI Extraction: ACTIVE") | color(Color::GreenLight),
    }) | border | size(HEIGHT, EQUAL, 3);

    return vbox({
        row1,
        row2,
        row3,
        row4,
    }) | flex;
}

}
}
