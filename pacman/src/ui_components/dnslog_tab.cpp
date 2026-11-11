#include "ui_components/dnslog_tab.h"
#include "ui_components/common.h"

namespace PacMan {
namespace UI {

using namespace ftxui;

Element dnsLogPanel(const StatsSnapshot& s) {
    Elements rows;

    // Title with count
    rows.push_back(hbox({
        text(" DNS / SNI Query Log") | bold | color(Color::BlueLight),
        filler(),
        text(std::to_string(s.dns_queries.size()) + " queries captured ") | color(Color::GrayLight),
    }));
    rows.push_back(separator());

    // Column headers
    rows.push_back(hbox({
        text("#")      | size(WIDTH, EQUAL, 5)  | bold | color(Color::GrayLight),
        text("TIME")   | size(WIDTH, EQUAL, 10) | bold | color(Color::GrayLight),
        text("TYPE")   | size(WIDTH, EQUAL, 7)  | bold | color(Color::GrayLight),
        text("SRC IP") | size(WIDTH, EQUAL, 18) | bold | color(Color::GrayLight),
        text("QUERY")  | flex                   | bold | color(Color::GrayLight),
    }));
    rows.push_back(separator());

    if (s.dns_queries.empty()) {
        rows.push_back(text("  No DNS/SNI queries observed yet.") | color(Color::GrayLight));
    }

    auto timeFormat = [](std::chrono::system_clock::time_point ts) {
        std::time_t t = std::chrono::system_clock::to_time_t(ts);
        std::tm tm_buf;
        localtime_r(&t, &tm_buf);
        char buf[16];
        std::strftime(buf, sizeof(buf), "%H:%M:%S", &tm_buf);
        return std::string(buf);
    };

    // Infer query type from the query string
    auto inferType = [](const std::string& q) -> std::pair<std::string, Color> {
        if (q.find("in-addr.arpa") != std::string::npos ||
            q.find("ip6.arpa")     != std::string::npos)
            return {"PTR", Color::Magenta};
        if (q.find("_tcp") != std::string::npos ||
            q.find("_udp") != std::string::npos)
            return {"SRV", Color::Yellow};
        if (q.find("_dmarc") != std::string::npos ||
            q.find("_domainkey") != std::string::npos)
            return {"TXT", Color::BlueLight};
        if (q.find("xn--") != std::string::npos)
            return {"IDN", Color::Orange1};
        // If it looks like an SNI hostname (contains letters, no query marker)
        if (q.find('.') != std::string::npos)
            return {"A/SNI", Color::CyanLight};
        return {"DNS", Color::GrayLight};
    };

    // Show newest first, up to 100
    std::size_t row_num = s.dns_queries.size();
    std::size_t shown = 0;
    for (auto it = s.dns_queries.rbegin(); it != s.dns_queries.rend() && shown < 100; ++it, ++shown) {
        auto [type_str, type_col] = inferType(it->query);
        rows.push_back(hbox({
            text(std::to_string(row_num--) + " ") | size(WIDTH, EQUAL, 5)  | color(Color::GrayLight),
            text(timeFormat(it->timestamp))        | size(WIDTH, EQUAL, 10) | color(Color::GrayLight),
            text(type_str)                         | size(WIDTH, EQUAL, 7)  | color(type_col) | bold,
            text(truncate(it->source_ip, 17))      | size(WIDTH, EQUAL, 18) | color(Color::White),
            text(it->query)                        | flex                   | color(Color::CyanLight),
        }));
        rows.push_back(separatorLight() | color(Color::GrayLight));
    }

    // Footer
    rows.push_back(separator());
    rows.push_back(hbox({
        text("  Types: A/SNI = hostname  PTR = reverse  SRV = service  TXT = record  IDN = intl domain  ")
            | color(Color::GrayLight),
    }));

    return vbox(rows) | border | flex;
}

}
}
