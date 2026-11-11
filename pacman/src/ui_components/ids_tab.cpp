#include "ui_components/ids_tab.h"
#include "ui_components/common.h"
#include <chrono>
#include <sstream>

namespace PacMan {
namespace UI {

using namespace ftxui;

// ---- Compact alerts panel (for Overview tab) --------------------------------
Element alertsMiniPanel(const StatsSnapshot& s) {
    Elements rows;

    int high_cnt = 0, med_cnt = 0, low_cnt = 0;
    for (const auto& a : s.alerts) {
        if (a.severity == Severity::HIGH) high_cnt++;
        else if (a.severity == Severity::MEDIUM) med_cnt++;
        else low_cnt++;
    }

    rows.push_back(hbox({
        text(" Alerts") | bold | color(Color::BlueLight),
        filler(),
        text(std::to_string(s.alerts.size()) + " total ") | color(
            s.alerts.empty() ? Color::GreenLight : Color::RedLight),
    }));
    rows.push_back(separator());

    // Severity summary line
    rows.push_back(hbox({
        text(" HIGH ") | color(Color::Red) | bold,
        text(std::to_string(high_cnt)) | color(Color::Red) | bold,
        text("  MED ") | color(Color::Yellow) | bold,
        text(std::to_string(med_cnt)) | color(Color::Yellow) | bold,
        text("  LOW ") | color(Color::GreenLight) | bold,
        text(std::to_string(low_cnt)) | color(Color::GreenLight) | bold,
        filler(),
    }));
    rows.push_back(separatorLight());

    // Column headers
    rows.push_back(hbox({
        text("SEV")  | size(WIDTH, EQUAL, 6)  | bold | color(Color::GrayLight),
        text("TIME") | size(WIDTH, EQUAL, 10) | bold | color(Color::GrayLight),
        text("SRC")  | size(WIDTH, EQUAL, 17) | bold | color(Color::GrayLight),
        text("DESCRIPTION") | flex            | bold | color(Color::GrayLight),
    }));
    rows.push_back(separatorLight());

    auto timeFormat = [](std::chrono::system_clock::time_point ts) {
        std::time_t t = std::chrono::system_clock::to_time_t(ts);
        std::tm tm_buf;
        localtime_r(&t, &tm_buf);
        char buf[12];
        std::strftime(buf, sizeof(buf), "%H:%M:%S", &tm_buf);
        return std::string(buf);
    };

    if (s.alerts.empty()) {
        rows.push_back(text("  ✓ No alerts — system clean") | color(Color::GreenLight));
    } else {
        // Show last 12 alerts, newest first
        const std::size_t limit = std::min<std::size_t>(s.alerts.size(), 12);
        std::size_t shown = 0;
        for (auto it = s.alerts.rbegin(); it != s.alerts.rend() && shown < limit; ++it, ++shown) {
            Color sev_col = severityColor(it->severity);
            rows.push_back(hbox({
                text(severityBadge(it->severity)) | size(WIDTH, EQUAL, 6)  | color(sev_col),
                text(timeFormat(it->timestamp))   | size(WIDTH, EQUAL, 10) | color(Color::GrayLight),
                text(truncate(it->source_ip, 16)) | size(WIDTH, EQUAL, 17) | color(Color::CyanLight),
                text(truncate(it->description, 40)) | flex                  | color(Color::White),
            }));
        }
    }

    return vbox(rows) | border | flex;
}

Element idsPanel(const StatsSnapshot& s) {
    int high_cnt = 0, med_cnt = 0, low_cnt = 0;
    for (const auto& a : s.alerts) {
        if (a.severity == Severity::HIGH) high_cnt++;
        else if (a.severity == Severity::MEDIUM) med_cnt++;
        else low_cnt++;
    }

    auto metricCard = [](const std::string& label, const std::string& val, Color col) {
        return vbox({
            text(label) | center | color(Color::GrayLight),
            separatorLight(),
            text(val) | bold | center | color(col),
        }) | border | size(HEIGHT, EQUAL, 5) | flex;   // border + label + separator + value
    };

    // Row 1
    auto row1 = hbox({
        vbox({
            text(" SEVERITY ALARM COUNTERS") | center | color(Color::GrayLight),
            separatorLight(),
            hbox({
                text(" HIGH: " + std::to_string(high_cnt) + " ") | color(Color::Red) | bold,
                text(" MED: " + std::to_string(med_cnt) + " ") | color(Color::Yellow) | bold,
                text(" LOW: " + std::to_string(low_cnt) + " ") | color(Color::GreenLight) | bold,
            }) | center,
        }) | border | size(HEIGHT, EQUAL, 5) | flex,
        metricCard("THREAT SIGNATURE ENGINE STATUS",
                   s.threat_intel.checked_domains > 0
                       ? "ACTIVE (VirusTotal: " + std::to_string(s.threat_intel.checked_domains) + " lookups)"
                       : "ACTIVE (local detectors)", Color::GreenLight),
    });

    // Row 2
    Elements timeline_rows;
    timeline_rows.push_back(text(" Live Internal IDS Threat Detection Timeline") | bold | color(Color::BlueLight));
    timeline_rows.push_back(separatorLight());
    timeline_rows.push_back(hbox({
        text("SEVERITY") | size(WIDTH, EQUAL, 10) | bold | color(Color::GrayLight),
        text("TRIGGER TIME") | size(WIDTH, EQUAL, 14) | bold | color(Color::GrayLight),
        text("SIGNATURE RULE / DESC") | flex | bold | color(Color::GrayLight),
        text("ATTACKER SOURCE") | size(WIDTH, EQUAL, 18) | bold | color(Color::GrayLight),
        text("TARGET APP") | size(WIDTH, EQUAL, 16) | bold | color(Color::GrayLight),
    }));
    timeline_rows.push_back(separatorLight());

    auto timeFormat = [](std::chrono::system_clock::time_point ts) {
        std::time_t t = std::chrono::system_clock::to_time_t(ts);
        std::tm tm_buf;
        localtime_r(&t, &tm_buf);
        char buf[16];
        std::strftime(buf, sizeof(buf), "%H:%M:%S", &tm_buf);
        return std::string(buf);
    };

    if (s.alerts.empty()) {
        timeline_rows.push_back(text("  No alerts detected") | color(Color::GrayLight));
    }

    std::size_t shown = 0;
    for (auto it = s.alerts.rbegin(); it != s.alerts.rend() && shown < 15; ++it, ++shown) {
        timeline_rows.push_back(hbox({
            text(severityBadge(it->severity)) | size(WIDTH, EQUAL, 10) | color(severityColor(it->severity)),
            text(timeFormat(it->timestamp)) | size(WIDTH, EQUAL, 14) | color(Color::GrayLight),
            text(truncate(it->description, 50)) | flex | color(Color::White),
            text(truncate(it->source_ip, 17)) | size(WIDTH, EQUAL, 18) | color(Color::CyanLight),
            text(truncate(it->alert_type.empty() ? "Generic" : it->alert_type, 15)) | size(WIDTH, EQUAL, 16) | color(Color::Yellow),
        }));
        timeline_rows.push_back(separatorLight() | color(Color::GrayLight));
    }
    auto row2 = vbox(timeline_rows) | border | flex;

    // Row 3
    Elements payload_elements;
    payload_elements.push_back(text(" DEEP PACKET PAYLOAD ANALYZER") | color(Color::GrayLight));
    payload_elements.push_back(separatorLight());

    std::string rule_id = "N/A";
    std::string rule_class = "Clean";
    std::string rule_info = "No threats detected";
    Color rule_color = Color::GreenLight;

    if (!s.alerts.empty()) {
        const Alert& last_alert = s.alerts.back();
        rule_id = last_alert.alert_type.empty() ? "GENERIC" : last_alert.alert_type;
        rule_class = severityToString(last_alert.severity);
        rule_info = last_alert.description;
        if (last_alert.severity == Severity::HIGH) rule_color = Color::Red;
        else if (last_alert.severity == Severity::MEDIUM) rule_color = Color::Yellow;

        std::stringstream ss(last_alert.payload_hex);
        std::string line;
        while (std::getline(ss, line)) {
            if (!line.empty()) {
                payload_elements.push_back(text(line) | color(Color::GrayLight));
            }
        }
    } else {
        payload_elements.push_back(text("  No alert payload data available") | color(Color::GrayLight));
    }

    auto row3 = vbox({
        text(" Selected Alert Details") | bold | color(Color::BlueLight),
        separatorLight(),
        hbox({
            vbox(payload_elements) | flex,
            separatorLight(),
            vbox({
                text(" SIGNATURE PROFILE") | color(Color::GrayLight),
                separatorLight(),
                text(" Rule ID: " + rule_id) | color(Color::Yellow),
                text(" Class: " + rule_class) | color(rule_color),
                text(" Info: " + rule_info) | color(Color::White),
            }) | size(WIDTH, EQUAL, 35),
        }),
    }) | border | size(HEIGHT, EQUAL, 10);

    // Row 4
    auto row4 = hbox({
        text(" ENGINE: ") | bold | color(Color::Yellow),
        text(" Detectors: 5 (port scan, SYN flood, high connections, large transfer, unknown domain) │ Alerts: " +
             std::to_string(s.alerts.size()) + " │ Capture: libpcap") | color(Color::CyanLight),
    }) | border | size(HEIGHT, EQUAL, 3);

    return vbox({
        row1,
        row2,
        row3,
        row4
    }) | flex;
}

}
}
