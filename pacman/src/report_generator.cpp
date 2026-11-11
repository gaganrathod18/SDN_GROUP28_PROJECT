#include "report_generator.h"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <vector>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <utility>

namespace PacMan {

ReportGenerator::ReportGenerator(std::string base_dir) : base_dir_(std::move(base_dir)) {}

std::string ReportGenerator::generateTimestampedPath(const std::string& extension, bool is_live) const {
    const std::string sub_dir = is_live ? "live" : "manual";
    const std::filesystem::path target_dir = std::filesystem::path(base_dir_) / sub_dir;
    
    // Create the directories if they don't exist
    std::error_code ec;
    std::filesystem::create_directories(target_dir, ec);
    if (ec) {
        std::cerr << "Warning: Failed to create report directory: " << target_dir << "\n";
    }

    // Generate the timestamp: YYYY-MM-DD_HH-MM-SS
    const std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    const std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm = *std::localtime(&now_c);
    
    std::ostringstream filename;
    filename << std::put_time(&now_tm, "%Y-%m-%d_%H-%M-%S") << extension;
    
    return (target_dir / filename.str()).string();
}

bool ReportGenerator::generateConsoleSummary(const StatsSnapshot& snapshot) const {
    std::cout << "\nPacMan Analysis Summary\n";
    std::cout << "=======================\n";
    std::cout << "Packets  : " << snapshot.total_packets << "\n";
    std::cout << "Bytes    : " << snapshot.total_bytes << "\n";
    std::cout << "TCP pkts : " << snapshot.tcp_packets << "\n";
    std::cout << "UDP pkts : " << snapshot.udp_packets << "\n";
    std::cout << "Other    : " << snapshot.other_packets << "\n";
    std::cout << "Flows    : " << snapshot.active_flows << "\n";
    std::cout << "Alerts   : " << snapshot.alerts.size() << "\n\n";

    std::cout << "Traffic breakdown:\n";
    for (const std::pair<const std::string, uint64_t>& entry : snapshot.traffic_by_class) {
        std::cout << "  " << entry.first << ": " << entry.second << " bytes\n";
    }

    if (!snapshot.top_domains.empty()) {
        std::cout << "\nTop domains:\n";
        // Sort by hit count descending.
        std::vector<std::pair<std::string, uint64_t>> domains(
            snapshot.top_domains.begin(), snapshot.top_domains.end());
        std::sort(domains.begin(), domains.end(),
                  [](const std::pair<std::string, uint64_t>& a, const std::pair<std::string, uint64_t>& b){ return a.second > b.second; });
        const std::size_t limit = std::min<std::size_t>(domains.size(), 10);
        for (std::size_t i = 0; i < limit; ++i) {
            std::cout << "  " << domains[i].first << " (" << domains[i].second << " pkts)\n";
        }
    }

    if (!snapshot.alerts.empty()) {
        std::cout << "\nAlerts:\n";
        for (const Alert& alert : snapshot.alerts) {
            std::cout << "  [" << severityToString(alert.severity) << "] "
                      << alert.source_ip << " - " << alert.description << "\n";
        }
    }
    return true;
}

bool ReportGenerator::generateCsv(const StatsSnapshot& snapshot, bool is_live) const {
    const std::string path = generateTimestampedPath(".csv", is_live);
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }

    // ---- Flow rows ----
    file << "record_type,timestamp,src,dst,protocol,classification,hostname,bytes\n";
    for (const Flow& flow : snapshot.recent_flows) {
        file << "flow,"
             << formatTime(flow.last_seen) << ","
             << flow.key.src_ip << ":" << flow.key.src_port << ","
             << flow.key.dst_ip << ":" << flow.key.dst_port << ","
             << protocolToString(flow.key.protocol) << ","
             << flow.classification << ","
             << flow.hostname << ","
             << flow.bytes << "\n";
    }

    // ---- Alert rows — separate section ----
    file << "\nrecord_type,timestamp,source_ip,severity,description\n";
    for (const Alert& alert : snapshot.alerts) {
        file << "alert,"
             << formatTime(alert.timestamp) << ","
             << alert.source_ip << ","
             << severityToString(alert.severity) << ","
             << alert.description << "\n";
    }
    return true;
}

bool ReportGenerator::generateHtml(const StatsSnapshot& snapshot, bool is_live) const {
    const std::string path = generateTimestampedPath(".html", is_live);
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }

    file << R"(<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PacMan Report</title>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #0d1117; color: #c9d1d9; }
    .header { background: linear-gradient(135deg, #1f6feb 0%, #388bfd 100%);
              padding: 24px 40px; }
    .header h1 { margin: 0; color: #fff; font-size: 1.8rem; }
    .header p  { margin: 4px 0 0; color: #cce; font-size: 0.9rem; }
    .content { padding: 24px 40px; }
    .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                 gap: 16px; margin-bottom: 32px; }
    .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                 padding: 16px; text-align: center; }
    .stat-card .val { font-size: 2rem; font-weight: 700; color: #58a6ff; }
    .stat-card .lbl { font-size: 0.75rem; color: #8b949e; margin-top: 4px; }
    h2 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; margin-top: 32px; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 0.85rem; }
    th, td { border: 1px solid #30363d; padding: 8px 12px; text-align: left; }
    th { background: #161b22; color: #8b949e; font-weight: 600; }
    tr:nth-child(even) { background: #0d1117; }
    tr:nth-child(odd)  { background: #161b22; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
             font-size: 0.75rem; font-weight: 600; }
    .HIGH   { background: #da3633; color: #fff; }
    .MEDIUM { background: #d29922; color: #000; }
    .LOW    { background: #238636; color: #fff; }
  </style>
</head>
<body>
<div class="header">
  <h1>&#x1F4E6; PacMan Analysis Report</h1>
  <p>Packet Analysis &amp; Cyber Monitoring</p>
</div>
<div class="content">
)";

    // --- Stat cards ---
    file << "<div class=\"stat-grid\">\n";
    auto card = [&](const std::string& label, uint64_t val) {
        file << "  <div class=\"stat-card\">"
             << "<div class=\"val\">" << val << "</div>"
             << "<div class=\"lbl\">" << label << "</div>"
             << "</div>\n";
    };
    card("Packets",     snapshot.total_packets);
    card("Bytes",       snapshot.total_bytes);
    card("TCP Packets", snapshot.tcp_packets);
    card("UDP Packets", snapshot.udp_packets);
    card("Active Flows",snapshot.active_flows);
    card("Alerts",      snapshot.alerts.size());
    file << "</div>\n";

    // --- Traffic Breakdown ---
    file << "<h2>Traffic Breakdown</h2>\n";
    file << "<table><tr><th>Classification</th><th>Bytes</th></tr>\n";
    for (const std::pair<const std::string, uint64_t>& entry : snapshot.traffic_by_class) {
        file << "<tr><td>" << entry.first << "</td><td>" << entry.second << "</td></tr>\n";
    }
    file << "</table>\n";

    // --- Top Domains ---
    if (!snapshot.top_domains.empty()) {
        std::vector<std::pair<std::string, uint64_t>> domains(
            snapshot.top_domains.begin(), snapshot.top_domains.end());
        std::sort(domains.begin(), domains.end(),
                  [](const std::pair<std::string, uint64_t>& a, const std::pair<std::string, uint64_t>& b){ return a.second > b.second; });
        file << "<h2>Top Domains</h2>\n";
        file << "<table><tr><th>Domain</th><th>Packets</th></tr>\n";
        const std::size_t limit = std::min<std::size_t>(domains.size(), 20);
        for (std::size_t i = 0; i < limit; ++i) {
            file << "<tr><td>" << domains[i].first << "</td><td>" << domains[i].second << "</td></tr>\n";
        }
        file << "</table>\n";
    }

    // --- Recent Flows ---
    if (!snapshot.recent_flows.empty()) {
        file << "<h2>Recent Connections</h2>\n";
        file << "<table><tr><th>Last Seen</th><th>Source</th><th>Destination</th>"
             << "<th>Protocol</th><th>Classification</th><th>Hostname</th><th>Bytes</th></tr>\n";
        for (const Flow& flow : snapshot.recent_flows) {
            file << "<tr>"
                 << "<td>" << formatTime(flow.last_seen) << "</td>"
                 << "<td>" << flow.key.src_ip << ":" << flow.key.src_port << "</td>"
                 << "<td>" << flow.key.dst_ip << ":" << flow.key.dst_port << "</td>"
                 << "<td>" << protocolToString(flow.key.protocol) << "</td>"
                 << "<td>" << flow.classification << "</td>"
                 << "<td>" << flow.hostname << "</td>"
                 << "<td>" << flow.bytes << "</td>"
                 << "</tr>\n";
        }
        file << "</table>\n";
    }

    // --- Alerts ---
    file << "<h2>Alerts</h2>\n";
    if (snapshot.alerts.empty()) {
        file << "<p>No alerts generated.</p>\n";
    } else {
        file << "<table><tr><th>Time</th><th>Source IP</th><th>Severity</th><th>Description</th></tr>\n";
        for (const Alert& alert : snapshot.alerts) {
            const std::string sev = severityToString(alert.severity);
            file << "<tr>"
                 << "<td>" << formatTime(alert.timestamp) << "</td>"
                 << "<td>" << alert.source_ip << "</td>"
                 << "<td><span class=\"badge " << sev << "\">" << sev << "</span></td>"
                 << "<td>" << alert.description << "</td>"
                 << "</tr>\n";
        }
        file << "</table>\n";
    }

    file << "</div>\n</body>\n</html>\n";
    return true;
}

} // namespace PacMan
