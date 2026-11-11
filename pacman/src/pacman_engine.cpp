#include "pacman_engine.h"
#include "dashboard.h"
#include "report_generator.h"
#include "sni_extractor.h"
#include "thread_safe_queue.h"
#include <filesystem>
#include <iostream>
#include <thread>
#include <utility>
#include <optional>

#if defined(PACMAN_HAVE_PCAP)
#include <pcap/pcap.h>
#endif

namespace PacMan {

namespace {

Protocol toProtocol(const PacketAnalyzer::ParsedPacket& parsed) {
    if (parsed.has_tcp) return Protocol::TCP;
    if (parsed.has_udp) return Protocol::UDP;
    return Protocol::OTHER;
}

std::string extractHostname(const PacketAnalyzer::ParsedPacket& parsed) {
    if (parsed.payload_data == nullptr || parsed.payload_length == 0) {
        return {};
    }

    if (parsed.has_tcp) {
        if (std::optional<std::string> sni = DPI::SNIExtractor::extract(parsed.payload_data, parsed.payload_length)) {
            return *sni;
        }
        if (std::optional<std::string> host = DPI::HTTPHostExtractor::extract(parsed.payload_data, parsed.payload_length)) {
            return *host;
        }
    }

    if (parsed.has_udp && (parsed.src_port == 53 || parsed.dest_port == 53)) {
        if (std::optional<std::string> dns = DPI::DNSExtractor::extractQuery(parsed.payload_data, parsed.payload_length)) {
            return *dns;
        }
    }

    return {};
}

} // namespace

PacManEngine::PacManEngine(Config config)
    : config_(std::move(config)),
      detector_(config_),
      virus_total_(config_.virus_total_api_key) {
    logger_.open(config_.log_file);
    firewall_.configure(config_.firewall_mode, config_.blocklist_file, config_.block_cooldown_s);
    statistics_.setFirewallMode(config_.firewall_mode, config_.blocklist_file);
    logger_.info("Firewall mode: " + config_.firewall_mode +
                 (config_.firewall_mode == "sdn" ? " (blocklist " + config_.blocklist_file + ")" : ""));
}

int PacManEngine::analyzeFile(const std::string& pcap_path) {
    logger_.info("Starting offline analysis for " + pcap_path);
    // A recording is history: never turn its alerts into blocks on the live network.
    firewall_.configure("passive", config_.blocklist_file, config_.block_cooldown_s);
    statistics_.setFirewallMode("passive", config_.blocklist_file);
    if (config_.firewall_mode == "sdn") {
        logger_.info("Offline analysis: firewall_mode=sdn ignored, no block requests are written");
    }
    PacketAnalyzer::PcapReader reader;
    if (!reader.open(pcap_path)) {
        logger_.error("Could not open PCAP file: " + pcap_path);
        return 1;
    }

    PacketAnalyzer::RawPacket raw;
    while (reader.readNextPacket(raw)) {
        (void)processOfflinePacket(pcap_path, raw);
    }

    std::filesystem::create_directories(config_.reports_dir);
    const StatsSnapshot snapshot = statistics_.snapshot();
    ReportGenerator reports(config_.reports_dir);
    reports.generateConsoleSummary(snapshot);
    reports.generateCsv(snapshot, false); // false = manual/offline report
    reports.generateHtml(snapshot, false);
    logger_.info("Offline analysis complete");
    return 0;
}

int PacManEngine::runLive() {
#if defined(PACMAN_HAVE_PCAP)
    logger_.info("Starting live capture on interface " + config_.interface_name);
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* handle = pcap_open_live(config_.interface_name.c_str(), 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        logger_.error(std::string("pcap_open_live failed: ") + errbuf);
        std::cerr << "PacMan live failed: " << errbuf << "\n";
        return 1;
    }

    DPI::ThreadSafeQueue<PacketAnalyzer::RawPacket> queue(config_.queue_size);
    std::atomic<bool> running{true};

    std::thread processing([&] {
        while (running.load() || !queue.empty()) {
            std::optional<PacketAnalyzer::RawPacket> packet = queue.popWithTimeout(std::chrono::milliseconds(100));
            if (packet) {
                (void)processOfflinePacket(config_.interface_name, *packet);
            }
        }
    });

    Dashboard dashboard(config_, statistics_);
    std::thread ui([&] { dashboard.run(running); });

    // Capture health, logged every 5 s: what the kernel delivered and dropped, and what PacMan
    // itself had to drop because the processing queue was full.
    uint64_t queue_drops = 0;
    std::chrono::steady_clock::time_point next_stats = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    auto log_capture_stats = [&]() {
        pcap_stat ps{};
        if (pcap_stats(handle, &ps) == 0) {
            logger_.info("Capture stats: received " + std::to_string(ps.ps_recv) +
                         ", kernel dropped " + std::to_string(ps.ps_drop) +
                         ", queue dropped " + std::to_string(queue_drops));
        }
    };

    while (running.load()) {
        if (std::chrono::steady_clock::now() >= next_stats) {
            log_capture_stats();
            next_stats += std::chrono::seconds(5);
        }
        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;
        const int result = pcap_next_ex(handle, &header, &data);
        if (result == 1 && header != nullptr && data != nullptr) {
            PacketAnalyzer::RawPacket raw;
            raw.header.ts_sec = static_cast<uint32_t>(header->ts.tv_sec);
            raw.header.ts_usec = static_cast<uint32_t>(header->ts.tv_usec);
            raw.header.incl_len = header->caplen;
            raw.header.orig_len = header->len;
            raw.data.assign(data, data + header->caplen);
            if (!queue.tryPush(std::move(raw))) {
                ++queue_drops;
            }
        } else if (result == PCAP_ERROR) {
            logger_.error(std::string("pcap_next_ex failed: ") + pcap_geterr(handle));
            running.store(false);
        }
    }

    log_capture_stats();
    queue.shutdown();
    if (processing.joinable()) processing.join();
    if (ui.joinable()) ui.join();
    pcap_close(handle);
    logger_.info("Live capture stopped");
    return 0;
#else
    logger_.error("Live mode requested, but libpcap was not found at build time");
    std::cerr << "Live mode requires libpcap. Install libpcap-devel and rebuild PacMan.\n";
    return 1;
#endif
}

bool PacManEngine::processOfflinePacket(const std::string& /*source_name*/, const PacketAnalyzer::RawPacket& raw) {
    PacketAnalyzer::ParsedPacket parsed;
    if (!PacketAnalyzer::PacketParser::parse(raw, parsed)) {
        logger_.warning("Skipping malformed packet");
        return false;
    }
    // Packet time, not wall-clock time: an offline file is read much faster than it was recorded.
    const ThreatDetector::Clock::time_point when{std::chrono::seconds(raw.header.ts_sec) +
                                                 std::chrono::microseconds(raw.header.ts_usec)};
    return processParsedPacket(parsed, raw.data.size(), when);
}

bool PacManEngine::processParsedPacket(const PacketAnalyzer::ParsedPacket& parsed, uint64_t packet_bytes,
                                       ThreatDetector::Clock::time_point when) {
    if (!parsed.has_ip) {
        return false;
    }

    FlowKey key;
    key.src_ip = parsed.src_ip;
    key.dst_ip = parsed.dest_ip;
    key.src_port = parsed.src_port;
    key.dst_port = parsed.dest_port;
    key.protocol = toProtocol(parsed);

    const std::string hostname = extractHostname(parsed);
    const std::string classification = classifier_.classify(hostname, key);
    Flow& flow = flow_tracker_.updateFlow(key, hostname, classification, packet_bytes, parsed.has_tcp, parsed.tcp_flags);

    if (parsed.has_tcp && parsed.payload_data != nullptr && parsed.payload_length > 0) {
        if (std::optional<DPI::TLSHandshakeInfo> tls_info = DPI::SNIExtractor::parseHandshake(parsed.payload_data, parsed.payload_length)) {
            flow.tls_version = tls_info->version;
            flow.cipher_suite = tls_info->cipher_suite;
            flow.ja3_fingerprint = tls_info->ja3_fingerprint;
        }
    }

    if (parsed.has_udp && (parsed.src_port == 53 || parsed.dest_port == 53) && !hostname.empty()) {
        statistics_.recordDns(hostname, parsed.src_ip);
    }

    statistics_.recordPacket(flow, packet_bytes, flow_tracker_.flows().size());

    // Did this packet open a connection started by its source? TCP: a bare SYN. Others: the first
    // packet of a flow whose reverse direction has not been seen (so replies are not counted).
    bool initiated = false;
    if (flow.packets == 1 && config_.detector_mode == "naive") {
        initiated = true;               // comparison mode: every new flow counts, replies included
    } else if (flow.packets == 1) {
        if (parsed.has_tcp) {
            initiated = (parsed.tcp_flags & 0x02) != 0 && (parsed.tcp_flags & 0x10) == 0;
        } else {
            FlowKey reverse{key.dst_ip, key.src_ip, key.dst_port, key.src_port, key.protocol};
            initiated = flow_tracker_.flows().count(reverse) == 0;
        }
    }

    for (Alert alert : detector_.inspectAt(flow, initiated, when)) {
        alert.hostname  = flow.hostname;
        alert.src_port  = flow.key.src_port;
        alert.dst_port  = flow.key.dst_port;
        
        // Format payload_hex
        if (parsed.payload_data != nullptr && parsed.payload_length > 0) {
            std::string hex_dump;
            size_t limit = std::min<size_t>(parsed.payload_length, 64);
            char line[128];
            for (size_t i = 0; i < limit; i += 16) {
                size_t row_len = std::min<size_t>(limit - i, 16);
                int offset = snprintf(line, sizeof(line), " %04zx: ", i);
                for (size_t j = 0; j < 16; j += 2) {
                    if (j < row_len) {
                        if (j + 1 < row_len) {
                            offset += snprintf(line + offset, sizeof(line) - offset, "%02x%02x ", parsed.payload_data[i+j], parsed.payload_data[i+j+1]);
                        } else {
                            offset += snprintf(line + offset, sizeof(line) - offset, "%02x00 ", parsed.payload_data[i+j]);
                        }
                    } else {
                        offset += snprintf(line + offset, sizeof(line) - offset, "     ");
                    }
                }
                hex_dump += std::string(line) + "\n";
            }
            alert.payload_hex = hex_dump;
        } else {
            alert.payload_hex = "  No payload data available\n";
        }

        if (flow.classification == "Unknown" && !flow.hostname.empty() && virus_total_.enabled()) {
            const VirusTotalResult result = virus_total_.checkDomain(flow.hostname);
            statistics_.recordThreatIntel(result.malicious);
            if (result.checked && result.malicious) {
                alert.severity = Severity::HIGH;
                alert.description += " (VirusTotal malicious)";
            } else if (!result.checked) {
                logger_.warning(result.message + " domain=" + flow.hostname);
            }
        }

        if (alert.severity == Severity::HIGH) {
            if (firewall_.blockIp(alert.source_ip, alert.description)) {
                logger_.warning("Block request written for " + alert.source_ip + " (" + alert.alert_type + ")");
            } else if (!firewall_.lastError().empty()) {
                logger_.error("Block request for " + alert.source_ip + " failed: " + firewall_.lastError());
            }
        }

        statistics_.recordAlert(alert);
        logger_.warning(alert.description + " source=" + alert.source_ip);
    }
    
    // Update firewall rules in statistics
    statistics_.updateFirewallRules(firewall_.getActiveRules());

    return true;
}

} // namespace PacMan
