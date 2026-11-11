#include "firewall_manager.h"
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>

namespace PacMan {

FirewallManager::FirewallManager() {
    initialize();
}

FirewallManager::~FirewallManager() {
    teardown();
}

bool FirewallManager::checkRoot() {
    // Passive simulated mode doesn't require root permissions anymore!
    return true;
}

void FirewallManager::runCommand(const std::string& /*cmd*/) {
    // Passive mode: We do NOT run any system iptables commands.
    // This keeps the Wi-Fi stable and prevents internet slowdowns.
}

void FirewallManager::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    initialized_ = true;
}

void FirewallManager::teardown() {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.clear();
    initialized_ = false;
}

void FirewallManager::configure(const std::string& mode, const std::string& blocklist_file, std::uint64_t cooldown_s) {
    std::lock_guard<std::mutex> lock(mutex_);
    sdn_mode_ = (mode == "sdn");
    blocklist_file_ = blocklist_file;
    cooldown_ = std::chrono::seconds(cooldown_s);
}

bool FirewallManager::blockIp(const std::string& ip, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_ || ip.empty()) {
        return false;
    }

    // One UI row per IP; repeated requests just bump the counter
    std::vector<FirewallRule>::iterator it = std::find_if(rules_.begin(), rules_.end(),
        [&ip](const FirewallRule& r) {
            return r.ip == ip;
        });
    if (it == rules_.end()) {
        FirewallRule rule;
        rule.target = sdn_mode_ ? "SDN_DROP" : "SIM_DROP";
        rule.ip = ip;
        rule.reason = reason;
        rule.drops = 1;
        rules_.push_back(rule);
    } else {
        it->drops += 1;
    }

    if (!sdn_mode_) {
        return false;
    }

    // Rate-limit per IP: the controller's drop rule already covers the cooldown period
    const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>::iterator last = last_request_.find(ip);
    if (last != last_request_.end() && now - last->second < cooldown_) {
        return false;
    }

    // One line per request: "<ip>\t<unix time>\t<reason>"; appended and flushed at once so the
    // controller never reads half a line.
    std::error_code ec;
    const std::filesystem::path path(blocklist_file_);
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
    }
    std::ofstream out(blocklist_file_, std::ios::app);
    if (!out) {
        last_error_ = "cannot open " + blocklist_file_;
        return false;
    }
    std::string clean_reason = reason;
    std::replace(clean_reason.begin(), clean_reason.end(), '\t', ' ');
    std::replace(clean_reason.begin(), clean_reason.end(), '\n', ' ');
    out << ip << '\t' << std::time(nullptr) << '\t' << clean_reason << '\n';
    out.flush();
    if (!out) {
        last_error_ = "write failed for " + blocklist_file_;
        return false;
    }
    last_request_[ip] = now;
    last_error_.clear();
    return true;
}

std::string FirewallManager::lastError() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_error_;
}

std::vector<FirewallRule> FirewallManager::getActiveRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_;
}

} // namespace PacMan
