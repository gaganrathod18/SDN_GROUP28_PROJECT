#include "config_manager.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace PacMan {

namespace {

/**
 * @brief Utility helper function to trim leading and trailing spaces and surrounding quotes.
 */
[[nodiscard]] std::string trim(std::string text_value) {
    auto is_not_whitespace = [](unsigned char character) { return !std::isspace(character); };
    
    // Trim leading whitespace
    text_value.erase(text_value.begin(), std::find_if(text_value.begin(), text_value.end(), is_not_whitespace));
    
    // Trim trailing whitespace
    text_value.erase(std::find_if(text_value.rbegin(), text_value.rend(), is_not_whitespace).base(), text_value.end());
    
    // Remove surrounding double quotes if present
    if (text_value.size() >= 2 && text_value.front() == '"' && text_value.back() == '"') {
        text_value = text_value.substr(1, text_value.size() - 2);
    }
    return text_value;
}

} // namespace

bool ConfigManager::load(const std::string& path) {
    std::ifstream config_file(path);
    if (!config_file.is_open()) {
        return false;
    }

    std::string current_line;
    while (std::getline(config_file, current_line)) {
        // Strip line comments starting with '#'
        const auto comment_position = current_line.find('#');
        if (comment_position != std::string::npos) {
            current_line = current_line.substr(0, comment_position);
        }

        // Look for the key-value separator '='
        const auto separator_position = current_line.find('=');
        if (separator_position == std::string::npos) {
            continue;
        }

        const std::string key = trim(current_line.substr(0, separator_position));
        const std::string value = trim(current_line.substr(separator_position + 1));
        if (!key.empty()) {
            applyValue(key, value);
        }
    }

    return true;
}

void ConfigManager::applyValue(const std::string& key, const std::string& value) {
    try {
        applyValueChecked(key, value);
    } catch (const std::exception&) {
        // A malformed number keeps the default instead of aborting start-up.
        std::cerr << "Warning: ignoring invalid value '" << value << "' for " << key << "\n";
    }
}

void ConfigManager::applyValueChecked(const std::string& key, const std::string& value) {
    if (key == "interface") {
        config_.interface_name = value;
    } else if (key == "reports_dir") {
        config_.reports_dir = value;
    } else if (key == "log_file") {
        config_.log_file = value;
    } else if (key == "virus_total_api_key") {
        config_.virus_total_api_key = value;
    } else if (key == "refresh_ms") {
        config_.refresh_ms = std::stoi(value);
    } else if (key == "queue_size") {
        config_.queue_size = static_cast<std::size_t>(std::stoul(value));
    } else if (key == "high_connection_threshold") {
        config_.high_connection_threshold = std::stoull(value);
    } else if (key == "port_scan_threshold") {
        config_.port_scan_threshold = std::stoull(value);
    } else if (key == "large_transfer_bytes") {
        config_.large_transfer_bytes = std::stoull(value);
    } else if (key == "detection_window_s") {
        config_.detection_window_s = std::max<std::uint64_t>(1, std::stoull(value));
    } else if (key == "syn_flood_threshold") {
        config_.syn_flood_threshold = std::stoull(value);
    } else if (key == "firewall_mode") {
        if (value != "passive" && value != "sdn") throw std::invalid_argument(value);
        config_.firewall_mode = value;
    } else if (key == "blocklist_file") {
        config_.blocklist_file = value;
    } else if (key == "block_cooldown_s") {
        config_.block_cooldown_s = std::stoull(value);
    } else if (key == "detector_mode") {
        if (value != "initiated" && value != "naive") throw std::invalid_argument(value);
        config_.detector_mode = value;
    }
}

} // namespace PacMan
