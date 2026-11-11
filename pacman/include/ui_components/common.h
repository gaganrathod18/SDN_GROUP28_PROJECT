#pragma once

#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ftxui/dom/elements.hpp>
#include "../shared_statistics.h"
#include "../pacman_types.h"

namespace PacMan {
namespace UI {

using namespace ftxui;

/**
 * @brief Formats a byte count into a human-readable string (B, KB, MB, GB).
 * @param bytes The number of bytes.
 * @return Formatted string.
 */
inline std::string fmtBytes(uint64_t bytes) {
    std::ostringstream ss;
    if (bytes >= 1024ULL * 1024ULL * 1024ULL)
        ss << std::fixed << std::setprecision(1) << (bytes / (1024.0 * 1024.0 * 1024.0)) << " GB";
    else if (bytes >= 1024ULL * 1024ULL)
        ss << std::fixed << std::setprecision(1) << (bytes / (1024.0 * 1024.0)) << " MB";
    else if (bytes >= 1024ULL)
        ss << std::fixed << std::setprecision(1) << (bytes / 1024.0) << " KB";
    else
        ss << bytes << " B";
    return ss.str();
}

/**
 * @brief Formats a bit/byte rate into a human-readable string.
 * @param bps The rate in bytes per second.
 * @return Formatted string.
 */
inline std::string fmtBytesRate(double bps) {
    std::ostringstream ss;
    if (bps >= 1024.0 * 1024.0 * 1024.0)
        ss << std::fixed << std::setprecision(1) << (bps / (1024.0 * 1024.0 * 1024.0)) << " GB/s";
    else if (bps >= 1024.0 * 1024.0)
        ss << std::fixed << std::setprecision(1) << (bps / (1024.0 * 1024.0)) << " MB/s";
    else if (bps >= 1024.0)
        ss << std::fixed << std::setprecision(1) << (bps / 1024.0) << " KB/s";
    else
        ss << static_cast<uint64_t>(bps) << " B/s";
    return ss.str();
}

/**
 * @brief Formats a packet count (K, M suffix).
 * @param n Number of packets.
 * @return Formatted string.
 */
inline std::string fmtPkts(uint64_t n) {
    if (n >= 1'000'000) return std::to_string(n / 1'000'000) + "M";
    if (n >= 1'000)     return std::to_string(n / 1'000) + "K";
    return std::to_string(n);
}

/**
 * @brief Truncates a string to a maximum length, appending an ellipsis if truncated.
 * @param s The string to truncate.
 * @param max_len Maximum allowed length.
 * @return Truncated string.
 */
inline std::string truncate(const std::string& s, std::size_t max_len) {
    if (s.size() <= max_len) return s;
    return s.substr(0, max_len - 1) + "…";
}

/**
 * @brief Maps an alert severity to an FTXUI color.
 * @param s The severity level.
 * @return The FTXUI color.
 */
inline Color severityColor(Severity s) {
    switch (s) {
        case Severity::HIGH:   return Color::Red;
        case Severity::MEDIUM: return Color::Yellow;
        case Severity::LOW:    return Color::GreenLight;
    }
    return Color::GreenLight;
}

/**
 * @brief Maps an alert severity to a text badge.
 * @param s The severity level.
 * @return A short text badge.
 */
inline std::string severityBadge(Severity s) {
    switch (s) {
        case Severity::HIGH:   return "⚠ HIGH  ";
        case Severity::MEDIUM: return "▲ MED   ";
        case Severity::LOW:    return "● LOW   ";
    }
    return "● LOW   ";
}

/**
 * @brief Maps a traffic class string to an FTXUI color.
 * @param cls The classification string.
 * @return The FTXUI color.
 */
inline Color classColor(const std::string& cls) {
    if (cls == "HTTPS" || cls == "TLS") return Color::BlueLight;
    if (cls == "HTTP")                  return Color::Cyan;
    if (cls == "DNS")                   return Color::Yellow;
    if (cls == "SSH")                   return Color::Green;
    if (cls == "Google")   return Color::GreenLight;
    if (cls == "YouTube")  return Color::Red;
    if (cls == "GitHub")   return Color::GrayLight;
    if (cls == "Netflix")  return Color::Red;
    if (cls == "Amazon")   return Color::Orange1;
    if (cls == "Facebook") return Color::BlueLight;
    if (cls == "Twitter")  return Color::CyanLight;
    if (cls == "Discord")  return Color::Purple;
    if (cls == "Telegram") return Color::Blue;
    if (cls == "Spotify")  return Color::GreenLight;
    return Color::White;
}

} // namespace UI
} // namespace PacMan
