#include "ui_components/analytics_tab.h"
#include "ui_components/common.h"
#include <algorithm>
#include <unordered_map>
#include <vector>

namespace PacMan {
namespace UI {

using namespace ftxui;

Element analyticsPanel(const StatsSnapshot& s) {
    return hbox({
        domainsPanel(s) | flex,
        talkersPanel(s) | flex
    }) | flex;
}

// ---- Top Domains (domain + first seen src IP + traffic gauge) ---------------
Element domainsPanel(const StatsSnapshot& s) {
    Elements rows;
    rows.push_back(text(" Top Domains") | bold | color(Color::BlueLight));
    rows.push_back(separator());
    // Column header
    rows.push_back(hbox({
        text("#")      | size(WIDTH, EQUAL, 3)  | color(Color::GrayLight) | bold,
        text("DOMAIN") | size(WIDTH, EQUAL, 28) | color(Color::GrayLight) | bold,
        text("SRC IP") | size(WIDTH, EQUAL, 17) | color(Color::GrayLight) | bold,
        text("PKTS")   | size(WIDTH, EQUAL, 8)  | color(Color::GrayLight) | bold,
        text("TRAFFIC") | flex                  | color(Color::GrayLight) | bold,
    }));
    rows.push_back(separator());

    // Build domain -> first src IP map from recent_flows
    std::unordered_map<std::string, std::string> domain_to_ip;
    for (const auto& f : s.recent_flows) {
        if (!f.hostname.empty() && domain_to_ip.find(f.hostname) == domain_to_ip.end()) {
            domain_to_ip[f.hostname] = f.key.src_ip;
        }
    }

    std::vector<std::pair<std::string, std::uint64_t>> domains(
        s.top_domains.begin(), s.top_domains.end());
    std::sort(domains.begin(), domains.end(),
              [](const auto& l, const auto& r){ return l.second > r.second; });

    const std::size_t limit = std::min<std::size_t>(domains.size(), 7);
    const std::uint64_t max_pkts = limit > 0 ? domains[0].second : 1;
    if (limit == 0) {
        rows.push_back(text("No domains observed yet") | color(Color::GrayLight));
    }
    for (std::size_t i = 0; i < limit; ++i) {
        const std::string ip = [&]() -> std::string {
            auto it = domain_to_ip.find(domains[i].first);
            return (it != domain_to_ip.end()) ? it->second : "—";
        }();
        const float pct = static_cast<float>(domains[i].second) / static_cast<float>(max_pkts);
        // Pick colour that cycles through a palette
        const Color barCol = (i % 3 == 0) ? Color::CyanLight
                           : (i % 3 == 1) ? Color::BlueLight
                                          : Color::Magenta;
        rows.push_back(hbox({
            text(std::to_string(i + 1)) | size(WIDTH, EQUAL, 3) | color(Color::GrayLight),
            text(truncate(domains[i].first, 27)) | size(WIDTH, EQUAL, 28) | color(Color::CyanLight),
            text(truncate(ip, 16))               | size(WIDTH, EQUAL, 17) | color(Color::White),
            text(fmtPkts(domains[i].second))     | size(WIDTH, EQUAL, 8)  | color(Color::GrayLight),
            gauge(pct) | color(barCol) | flex,
        }));
    }
    return vbox(rows) | border | flex;
}

// ---- Top Talkers (IP + domain → bytes) ------------------------------------
Element talkersPanel(const StatsSnapshot& s) {
    Elements rows;
    rows.push_back(text(" Top Talkers") | bold | color(Color::BlueLight));
    rows.push_back(separator());
    // Column header
    rows.push_back(hbox({
        text("SRC IP")  | size(WIDTH, EQUAL, 17) | color(Color::GrayLight) | bold,
        text("DOMAIN")  | size(WIDTH, EQUAL, 22) | color(Color::GrayLight) | bold,
        text("BYTES")   | size(WIDTH, EQUAL, 10) | color(Color::GrayLight) | bold,
        text("")        | flex,
    }));
    rows.push_back(separator());

    // Build src_ip -> hostname map from recent_flows
    std::unordered_map<std::string, std::string> ip_to_domain;
    for (const auto& f : s.recent_flows) {
        if (!f.hostname.empty() && ip_to_domain.find(f.key.src_ip) == ip_to_domain.end()) {
            ip_to_domain[f.key.src_ip] = f.hostname;
        }
    }

    std::vector<std::pair<std::string, std::uint64_t>> talkers(
        s.top_talkers.begin(), s.top_talkers.end());
    std::sort(talkers.begin(), talkers.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    const std::uint64_t max_bytes = talkers.empty() ? 1 : talkers.front().second;
    const std::size_t limit = std::min<std::size_t>(talkers.size(), 5);

    if (limit == 0) {
        rows.push_back(text("No traffic yet") | color(Color::GrayLight));
    }
    for (std::size_t i = 0; i < limit; ++i) {
        const std::string& ip = talkers[i].first;
        const std::string domain = [&]() -> std::string {
            auto it = ip_to_domain.find(ip);
            return (it != ip_to_domain.end()) ? it->second : "—";
        }();
        const float pct = static_cast<float>(talkers[i].second) / static_cast<float>(max_bytes);
        // Multi-color palette for Top Talkers
        const Color barCol = (i % 4 == 0) ? Color::RedLight
                           : (i % 4 == 1) ? Color::Yellow
                           : (i % 4 == 2) ? Color::GreenLight
                                          : Color::BlueLight;
        rows.push_back(hbox({
            text(truncate(ip, 16))     | size(WIDTH, EQUAL, 17) | color(Color::White),
            text(truncate(domain, 21)) | size(WIDTH, EQUAL, 22) | color(Color::Cyan),
            text(fmtBytes(talkers[i].second)) | size(WIDTH, EQUAL, 10) | color(Color::GreenLight),
            gauge(pct) | color(barCol) | flex,
        }));
    }
    return vbox(rows) | border | flex;
}

}
}
