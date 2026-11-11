#include "ui_components/firewall_tab.h"
#include "ui_components/common.h"
#include <algorithm>
#include <chrono>

namespace PacMan {
namespace UI {

using namespace ftxui;

Element firewallPanel(const StatsSnapshot& s) {
    auto metricCard = [](const std::string& label, const std::string& val, Color col) {
        return vbox({
            text(label) | center | color(Color::GrayLight),
            separatorLight(),
            text(val) | bold | center | color(col),
        }) | border | size(HEIGHT, EQUAL, 5) | flex;   // border + label + separator + value
    };

    const bool sdn = s.firewall_mode == "sdn";
    std::uint64_t requests = 0;
    for (const auto& rule : s.firewall_rules) requests += rule.drops;

    // Row 1: real counters and the enforcement mode
    auto row1 = hbox({
        metricCard("BLOCKED IPs", std::to_string(s.firewall_rules.size()), Color::Red),
        metricCard("HIGH ALERTS ASKING FOR A BLOCK", std::to_string(requests), Color::RedLight),
        metricCard("ENFORCEMENT", sdn ? "SDN CONTROLLER" : "PASSIVE (RECORD ONLY)",
                   sdn ? Color::GreenLight : Color::Yellow),
    });

    // Row 2 (flex): one row per blocked IP
    Elements active_rules;
    active_rules.push_back(text(" Block Rules") | bold | color(Color::BlueLight));
    active_rules.push_back(separatorLight());
    active_rules.push_back(hbox({
        text("TARGET") | size(WIDTH, EQUAL, 10) | bold | color(Color::GrayLight),
        text("IP") | size(WIDTH, EQUAL, 20) | bold | color(Color::GrayLight),
        text("REQUESTS") | size(WIDTH, EQUAL, 10) | bold | color(Color::GrayLight),
        text("REASON") | flex | bold | color(Color::GrayLight),
    }));
    active_rules.push_back(separatorLight());

    if (s.firewall_rules.empty()) {
        active_rules.push_back(text("No rules currently active") | color(Color::GrayLight));
    } else {
        for (const auto& rule : s.firewall_rules) {
            active_rules.push_back(hbox({
                text(rule.target) | size(WIDTH, EQUAL, 10) | color(Color::Red),
                text(rule.ip) | size(WIDTH, EQUAL, 20) | color(Color::White),
                text(std::to_string(rule.drops)) | size(WIDTH, EQUAL, 10) | color(Color::White),
                text(rule.reason) | flex | color(Color::CyanLight),
            }));
        }
    }
    auto row2 = vbox(active_rules) | border | flex;

    // Row 3: where a block request goes in the current mode
    auto row3 = vbox({
        text(" How Blocks Are Enforced") | bold | color(Color::BlueLight),
        separatorLight(),
        text(sdn ? " HIGH alert -> attacker IP appended to " + s.blocklist_file +
                       " -> SDN controller installs OpenFlow drop rules on every switch"
                 : " Rules are only recorded here; no traffic is blocked (set firewall_mode=sdn to enforce)")
            | color(sdn ? Color::GreenLight : Color::Yellow),
    }) | border | size(HEIGHT, EQUAL, 5);

    // Row 4: protocol ratio from the real packet counters
    const std::uint64_t total = std::max<std::uint64_t>(1, s.total_packets);
    auto pct = [total](std::uint64_t n) { return std::to_string(n * 100 / total) + "%"; };
    auto row4 = vbox({
        text(" Protocol Ratio (all captured packets)") | bold | color(Color::BlueLight),
        separatorLight(),
        text(" TCP: " + pct(s.tcp_packets) + " | UDP: " + pct(s.udp_packets) + " | Other: " + pct(s.other_packets))
            | color(Color::CyanLight),
    }) | border | size(HEIGHT, EQUAL, 5);

    return vbox({
        row1,
        row2,
        row3,
        row4,
    }) | flex;
}

}
}
