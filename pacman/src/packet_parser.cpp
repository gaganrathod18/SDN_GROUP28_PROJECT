#include "packet_parser.h"
#include "platform.h"
#include <sstream>
#include <iomanip>
#include <cstring>

// Use portable byte order functions
using PortableNet::netToHost16;
using PortableNet::netToHost32;

// Wrapper macros for readability/compatibility
#define ntohs(x) netToHost16(x)
#define ntohl(x) netToHost32(x)

namespace PacketAnalyzer {

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    // Initialize parsed packet structure
    parsed = ParsedPacket();
    parsed.timestamp_sec = raw.header.ts_sec;
    parsed.timestamp_usec = raw.header.ts_usec;
    
    const uint8_t* raw_packet_data = raw.data.data();
    const size_t total_packet_len = raw.data.size();
    size_t offset = 0;
    
    // Parse Ethernet header first
    if (!parseEthernet(raw_packet_data, total_packet_len, parsed, offset)) {
        return false;
    }
    
    // Parse IP layer if it's an IPv4 packet
    if (parsed.ether_type == EtherType::IPv4) {
        if (!parseIPv4(raw_packet_data, total_packet_len, parsed, offset)) {
            return false;
        }
        
        // Parse transport layer based on protocol
        if (parsed.protocol == Protocol::TCP) {
            if (!parseTCP(raw_packet_data, total_packet_len, parsed, offset)) {
                return false;
            }
        } else if (parsed.protocol == Protocol::UDP) {
            if (!parseUDP(raw_packet_data, total_packet_len, parsed, offset)) {
                return false;
            }
        }
    }
    
    // Set payload information
    if (offset < total_packet_len) {
        parsed.payload_length = total_packet_len - offset;
        parsed.payload_data = raw_packet_data + offset;
    } else {
        parsed.payload_length = 0;
        parsed.payload_data = nullptr;
    }
    
    return true;
}

bool PacketParser::parseEthernet(const uint8_t* data, size_t len, 
                                  ParsedPacket& parsed, size_t& offset) {
    // Ethernet header is exactly 14 bytes
    constexpr size_t ETH_HEADER_LEN = 14;
    
    if (len < ETH_HEADER_LEN) {
        return false;  // Packet is truncated
    }
    
    // Parse destination MAC (bytes 0-5)
    parsed.dest_mac = macToString(data);
    
    // Parse source MAC (bytes 6-11)
    parsed.src_mac = macToString(data + 6);
    
    // Parse EtherType (bytes 12-13, big-endian)
    parsed.ether_type = ntohs(*reinterpret_cast<const uint16_t*>(data + 12));
    
    offset = ETH_HEADER_LEN;
    return true;
}

bool PacketParser::parseIPv4(const uint8_t* data, size_t len, 
                              ParsedPacket& parsed, size_t& offset) {
    // Minimum IPv4 header is 20 bytes
    constexpr size_t MIN_IP_HEADER_LEN = 20;
    
    if (len < offset + MIN_IP_HEADER_LEN) {
        return false;  // Packet too short
    }
    
    const uint8_t* ip_header_ptr = data + offset;
    
    // First byte: version (upper 4 bits) + IHL (lower 4 bits)
    const uint8_t version_ihl = ip_header_ptr[0];
    parsed.ip_version = (version_ihl >> 4) & 0x0F;
    const uint8_t ihl_word_count = version_ihl & 0x0F;  // Header length in 32-bit words
    
    if (parsed.ip_version != 4) {
        return false;  // Not IPv4
    }
    
    const size_t ip_header_len = ihl_word_count * 4;  // Convert word count to bytes
    if (ip_header_len < MIN_IP_HEADER_LEN || len < offset + ip_header_len) {
        return false;
    }
    
    // Parse remaining common fields
    parsed.ttl = ip_header_ptr[8];
    parsed.protocol = ip_header_ptr[9];
    
    // Source IP (bytes 12-15). Use memcpy to avoid unaligned read undefined behavior.
    uint32_t raw_src_ip;
    std::memcpy(&raw_src_ip, ip_header_ptr + 12, 4);
    parsed.src_ip = ipToString(raw_src_ip);
    
    // Destination IP (bytes 16-19). Use memcpy to avoid unaligned read undefined behavior.
    uint32_t raw_dest_ip;
    std::memcpy(&raw_dest_ip, ip_header_ptr + 16, 4);
    parsed.dest_ip = ipToString(raw_dest_ip);
    
    parsed.has_ip = true;
    offset += ip_header_len;
    
    return true;
}

bool PacketParser::parseTCP(const uint8_t* data, size_t len, 
                             ParsedPacket& parsed, size_t& offset) {
    // Minimum TCP header is 20 bytes
    constexpr size_t MIN_TCP_HEADER_LEN = 20;
    
    if (len < offset + MIN_TCP_HEADER_LEN) {
        return false;
    }
    
    const uint8_t* tcp_header_ptr = data + offset;
    
    // Source port (bytes 0-1)
    parsed.src_port = ntohs(*reinterpret_cast<const uint16_t*>(tcp_header_ptr));
    
    // Destination port (bytes 2-3)
    parsed.dest_port = ntohs(*reinterpret_cast<const uint16_t*>(tcp_header_ptr + 2));
    
    // Sequence number (bytes 4-7)
    parsed.seq_number = ntohl(*reinterpret_cast<const uint32_t*>(tcp_header_ptr + 4));
    
    // Acknowledgment number (bytes 8-11)
    parsed.ack_number = ntohl(*reinterpret_cast<const uint32_t*>(tcp_header_ptr + 8));
    
    // Data offset (upper 4 bits of byte 12) - header length in 32-bit words
    const uint8_t data_offset_word_count = (tcp_header_ptr[12] >> 4) & 0x0F;
    const size_t tcp_header_len = data_offset_word_count * 4;
    
    // TCP Flags (byte 13)
    parsed.tcp_flags = tcp_header_ptr[13];
    
    if (tcp_header_len < MIN_TCP_HEADER_LEN || len < offset + tcp_header_len) {
        return false;
    }
    
    parsed.has_tcp = true;
    offset += tcp_header_len;
    
    return true;
}

bool PacketParser::parseUDP(const uint8_t* data, size_t len, 
                             ParsedPacket& parsed, size_t& offset) {
    // UDP header is always 8 bytes
    constexpr size_t UDP_HEADER_LEN = 8;
    
    if (len < offset + UDP_HEADER_LEN) {
        return false;
    }
    
    const uint8_t* udp_header_ptr = data + offset;
    
    // Source port (bytes 0-1)
    parsed.src_port = ntohs(*reinterpret_cast<const uint16_t*>(udp_header_ptr));
    
    // Destination port (bytes 2-3)
    parsed.dest_port = ntohs(*reinterpret_cast<const uint16_t*>(udp_header_ptr + 2));
    
    parsed.has_udp = true;
    offset += UDP_HEADER_LEN;
    
    return true;
}

std::string PacketParser::macToString(const uint8_t* mac) {
    std::ostringstream mac_stream;
    mac_stream << std::hex << std::setfill('0');
    for (int idx = 0; idx < 6; ++idx) {
        if (idx > 0) {
            mac_stream << ":";
        }
        mac_stream << std::setw(2) << static_cast<int>(mac[idx]);
    }
    return mac_stream.str();
}

std::string PacketParser::ipToString(uint32_t ip) {
    // Extract each byte from network byte order (big-endian)
    std::ostringstream ip_stream;
    ip_stream << ((ip >> 0) & 0xFF) << "."
              << ((ip >> 8) & 0xFF) << "."
              << ((ip >> 16) & 0xFF) << "."
              << ((ip >> 24) & 0xFF);
    return ip_stream.str();
}

std::string PacketParser::protocolToString(uint8_t protocol) {
    switch (protocol) {
        case Protocol::ICMP: 
            return "ICMP";
        case Protocol::TCP:  
            return "TCP";
        case Protocol::UDP:  
            return "UDP";
        default: 
            return "Unknown(" + std::to_string(protocol) + ")";
    }
}

std::string PacketParser::tcpFlagsToString(uint8_t flags) {
    std::string flags_summary;
    if (flags & TCPFlags::SYN) flags_summary += "SYN ";
    if (flags & TCPFlags::ACK) flags_summary += "ACK ";
    if (flags & TCPFlags::FIN) flags_summary += "FIN ";
    if (flags & TCPFlags::RST) flags_summary += "RST ";
    if (flags & TCPFlags::PSH) flags_summary += "PSH ";
    if (flags & TCPFlags::URG) flags_summary += "URG ";
    
    if (!flags_summary.empty()) {
        flags_summary.pop_back();  // Remove trailing space
    }
    return flags_summary.empty() ? "none" : flags_summary;
}

} // namespace PacketAnalyzer