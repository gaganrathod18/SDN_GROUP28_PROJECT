#include "pacman_types.h"
#include <ctime>
#include <iomanip>
#include <sstream>

namespace PacMan {

bool FlowKey::operator==(const FlowKey& other) const {
    return src_ip == other.src_ip &&
           dst_ip == other.dst_ip &&
           src_port == other.src_port &&
           dst_port == other.dst_port &&
           protocol == other.protocol;
}

std::string FlowKey::toString() const {
    std::ostringstream output_stream;
    output_stream << src_ip << ":" << src_port << " -> "
                  << dst_ip << ":" << dst_port << " "
                  << protocolToString(protocol);
    return output_stream.str();
}

std::size_t FlowKeyHash::operator()(const FlowKey& key) const {
    std::size_t combined_hash = 0;

    // Use a boost-like hash_combine magic constant (0x9e3779b9) to prevent hash collisions.
    // The constant 0x9e3779b9 is the golden ratio fractional part of 2^32, used to distribute bits.
    auto hash_combine = [&combined_hash](std::size_t field_hash) {
        combined_hash ^= field_hash + 0x9e3779b9 + (combined_hash << 6) + (combined_hash >> 2);
    };

    hash_combine(std::hash<std::string>{}(key.src_ip));
    hash_combine(std::hash<std::string>{}(key.dst_ip));
    hash_combine(std::hash<std::uint16_t>{}(key.src_port));
    hash_combine(std::hash<std::uint16_t>{}(key.dst_port));
    hash_combine(std::hash<int>{}(static_cast<int>(key.protocol)));

    return combined_hash;
}

std::string protocolToString(Protocol protocol) {
    switch (protocol) {
        case Protocol::TCP: 
            return "TCP";
        case Protocol::UDP: 
            return "UDP";
        default: 
            return "OTHER";
    }
}

std::string severityToString(Severity severity) {
    switch (severity) {
        case Severity::LOW: 
            return "LOW";
        case Severity::MEDIUM: 
            return "MEDIUM";
        case Severity::HIGH: 
            return "HIGH";
    }
    return "LOW";
}

std::string formatTime(std::chrono::system_clock::time_point time) {
    const std::time_t raw_time = std::chrono::system_clock::to_time_t(time);
    std::tm time_structure{};

    // Handle thread-safe and platform-specific conversion from epoch time to local calendar structure
#if defined(_MSC_VER)
    localtime_s(&time_structure, &raw_time);
#elif defined(__unix__) || defined(__APPLE__)
    localtime_r(&raw_time, &time_structure);
#else
    if (std::tm* local_time_ptr = std::localtime(&raw_time)) {
        time_structure = *local_time_ptr;
    }
#endif

    std::ostringstream time_stream;
    time_stream << std::put_time(&time_structure, "%Y-%m-%d %H:%M:%S");
    return time_stream.str();
}

} // namespace PacMan
