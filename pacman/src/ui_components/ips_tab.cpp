#include "ui_components/ips_tab.h"
#include "ui_components/common.h"
#include <chrono>
#include <algorithm>

namespace PacMan {
namespace UI {

using namespace ftxui;

Element ipsPanel(const StatsSnapshot& s) {
    auto metricCard = [](const std::string& label, const std::string& val, Color col) {
        return vbox({
            text(label) | center | color(Color::GrayLight),
            separatorLight(),
            text(val) | bold | center | color(col),
        }) | border | size(HEIGHT, EQUAL, 5) | flex;   // border + label + separator + value
    };

    // Row 1
    auto row1 = hbox({
        metricCard("TOTAL BANNED IPs", std::to_string(s.firewall_rules.size()), Color::Red),
        metricCard("AUTO-BAN HEURISTICS TRIGGER STATE", s.firewall_rules.empty() ? "IDLE" : "ACTIVE", Color::GreenLight),
    });

    // Row 2 (flex) - Matrix of rules
    Elements matrix_rows;
    matrix_rows.push_back(text(" IPS Mitigation Rules Matrix") | bold | color(Color::BlueLight));
    matrix_rows.push_back(separatorLight());
    matrix_rows.push_back(hbox({
        text("IP ADDRESS") | size(WIDTH, EQUAL, 16) | bold | color(Color::GrayLight),
        text("STATUS") | size(WIDTH, EQUAL, 10) | bold | color(Color::GrayLight),
        text("TRIGGER REASON") | flex | bold | color(Color::GrayLight),
        text("TARGET ACTION") | size(WIDTH, EQUAL, 16) | bold | color(Color::GrayLight),
    }));
    matrix_rows.push_back(separatorLight());

    if (s.firewall_rules.empty()) {
        matrix_rows.push_back(text("  No active IP bans enforced by IPS") | color(Color::GrayLight));
    } else {
        for (const auto& rule : s.firewall_rules) {
            matrix_rows.push_back(hbox({
                text(truncate(rule.ip, 15)) | size(WIDTH, EQUAL, 16) | color(Color::White),
                text("BANNED") | size(WIDTH, EQUAL, 10) | color(Color::Red),
                text(truncate(rule.reason, 50)) | flex | color(Color::White),
                text(rule.target + " (DROP)") | size(WIDTH, EQUAL, 16) | color(Color::CyanLight),
            }));
            matrix_rows.push_back(separatorLight() | color(Color::GrayLight));
        }
    }
    auto row2 = vbox(matrix_rows) | border | flex;

    // Row 3: Signature counters based on alerts
    int high_conn_cnt = 0;
    int port_scan_cnt = 0;
    int syn_flood_cnt = 0;
    int unknown_cnt = 0;
    for (const auto& a : s.alerts) {
        if (a.alert_type == "PORT_SCAN") port_scan_cnt++;
        else if (a.alert_type == "SYN_FLOOD") syn_flood_cnt++;
        else if (a.alert_type == "HIGH_CONN") high_conn_cnt++;
        else unknown_cnt++;
    }
    int total_threats = high_conn_cnt + port_scan_cnt + syn_flood_cnt + unknown_cnt;
    float high_conn_ratio = total_threats > 0 ? (float)high_conn_cnt / total_threats : 0.0f;
    float port_scan_ratio = total_threats > 0 ? (float)port_scan_cnt / total_threats : 0.0f;
    float syn_flood_ratio = total_threats > 0 ? (float)syn_flood_cnt / total_threats : 0.0f;
    float unknown_ratio = total_threats > 0 ? (float)unknown_cnt / total_threats : 0.0f;

    auto row3 = vbox({
        text(" Active IPS Attack Signature Chart") | bold | color(Color::BlueLight),
        separatorLight(),
        hbox({
            text(" High Conn ") | size(WIDTH, EQUAL, 12) | color(Color::White),
            gauge(high_conn_ratio) | color(Color::Red) | flex,
            text(" " + std::to_string(int(high_conn_ratio * 100)) + "% ") | color(Color::Red),
        }),
        hbox({
            text(" Portscan ") | size(WIDTH, EQUAL, 12) | color(Color::White),
            gauge(port_scan_ratio) | color(Color::Yellow) | flex,
            text(" " + std::to_string(int(port_scan_ratio * 100)) + "% ") | color(Color::Yellow),
        }),
        hbox({
            text(" SYN flood ") | size(WIDTH, EQUAL, 12) | color(Color::White),
            gauge(syn_flood_ratio) | color(Color::RedLight) | flex,
            text(" " + std::to_string(int(syn_flood_ratio * 100)) + "% ") | color(Color::RedLight),
        }),
        hbox({
            text(" Other ") | size(WIDTH, EQUAL, 12) | color(Color::White),
            gauge(unknown_ratio) | color(Color::BlueLight) | flex,
            text(" " + std::to_string(int(unknown_ratio * 100)) + "% ") | color(Color::BlueLight),
        }),
    }) | border | size(HEIGHT, EQUAL, 8);   // border + title + separator + 4 rows

    // Row 4: Real-time logs
    Elements execution_logs;
    execution_logs.push_back(text(" Real-Time Automated IPS Executions") | bold | color(Color::BlueLight));
    execution_logs.push_back(separatorLight());
    if (s.firewall_rules.empty()) {
        execution_logs.push_back(text("  Waiting for IPS heuristic triggers...") | color(Color::GrayLight));
    } else {
        for (const auto& rule : s.firewall_rules) {
            execution_logs.push_back(
                text(std::string(s.firewall_mode == "sdn" ? "  IPS AUTO-BLOCK: drop requested from SDN controller for "
                                                          : "  IPS (passive): would block ") +
                     rule.ip + " -> Reason: " + rule.reason)
                | color(Color::RedLight)
            );
        }
    }
    auto row4 = vbox(execution_logs) | border | size(HEIGHT, EQUAL, 6);

    // Row 5
    auto row5 = hbox({
        text(" MODE: ") | bold | color(Color::Yellow),
        text(s.firewall_mode == "sdn" ? " sdn: blocks are sent to the controller via " + s.blocklist_file
                                      : " passive: alerts are recorded, nothing is blocked") | color(Color::CyanLight),
    }) | border | size(HEIGHT, EQUAL, 3);

    return vbox({
        row1,
        row2,
        row3,
        row4,
        row5
    }) | flex;
}

}
}
