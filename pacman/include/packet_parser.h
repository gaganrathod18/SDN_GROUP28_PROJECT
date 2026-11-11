#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <array>
#include "pcap_reader.h"

namespace PacketAnalyzer {

/**
 * @brief Ethernet Frame Header structure (14 bytes).
 */
struct EthernetHeader {
    std::array<uint8_t, 6> dest_mac;    ///< Destination hardware MAC address
    std::array<uint8_t, 6> src_mac;     ///< Source hardware MAC address
    uint16_t ether_type;                 ///< Payload identifier (e.g. 0x0800 = IPv4)
};

/**
 * @brief IPv4 Header structure (usually 20 bytes).
 */
struct IPv4Header {
    uint8_t  version_ihl;      ///< Version (4 bits) + Internet Header Length (4 bits)
    uint8_t  tos;              ///< Type of Service
    uint16_t total_length;     ///< Total packet size (header + data payload)
    uint16_t identification;   ///< IP packet fragment ID
    uint16_t flags_fragment;   ///< Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t  ttl;              ///< Time To Live hop count limit
    uint8_t  protocol;         ///< Transport protocol (e.g. 6 = TCP, 17 = UDP)
    uint16_t checksum;         ///< Packet header parity checksum
    uint32_t src_ip;           ///< Source IP Address
    uint32_t dest_ip;          ///< Destination IP Address
};

/**
 * @brief TCP Segment Header structure (usually 20 bytes).
 */
struct TCPHeader {
    uint16_t src_port;         ///< Source TCP port
    uint16_t dest_port;        ///< Destination TCP port
    uint32_t seq_number;       ///< Sequence identifier
    uint32_t ack_number;       ///< Acknowledgment identifier
    uint8_t  data_offset;      ///< Data offset word count (4 bits) + Reserved (4 bits)
    uint8_t  flags;            ///< TCP flow control flags (SYN, ACK, FIN, RST)
    uint16_t window;           ///< Receiver window advertise size
    uint16_t checksum;         ///< Header + data verification checksum
    uint16_t urgent_pointer;   ///< Urgent pointer offset value
};

/**
 * @brief UDP Datagram Header structure (exactly 8 bytes).
 */
struct UDPHeader {
    uint16_t src_port;         ///< Source UDP port
    uint16_t dest_port;        ///< Destination UDP port
    uint16_t length;           ///< Length of UDP header + payload in bytes
    uint16_t checksum;         ///< Datagram verification checksum
};

/**
 * @brief Human-readable presentation format of a fully parsed packet structure.
 */
struct ParsedPacket {
    // Timestamps
    uint32_t timestamp_sec;      ///< Arrival time seconds
    uint32_t timestamp_usec;     ///< Arrival time microseconds

    // Ethernet layer details
    std::string src_mac;         ///< Printable source MAC ("XX:XX:XX:XX:XX:XX")
    std::string dest_mac;        ///< Printable destination MAC ("XX:XX:XX:XX:XX:XX")
    uint16_t ether_type;         ///< Parsed raw EtherType field

    // IP layer details
    bool has_ip = false;         ///< Flag indicating if IP layer is present
    uint8_t ip_version;          ///< IP Protocol Version (always 4 in this version)
    std::string src_ip;          ///< Printable source IP ("X.X.X.X")
    std::string dest_ip;         ///< Printable destination IP ("X.X.X.X")
    uint8_t protocol;            ///< Embedded Layer 4 protocol ID
    uint8_t ttl;                 ///< Time To Live hop count limit

    // Transport layer details
    bool has_tcp = false;        ///< Flag indicating if TCP header is parsed
    bool has_udp = false;        ///< Flag indicating if UDP header is parsed
    uint16_t src_port;           ///< Port number of packet source
    uint16_t dest_port;          ///< Port number of packet destination

    // TCP-specific details
    uint8_t tcp_flags;           ///< TCP control flag byte
    uint32_t seq_number;         ///< TCP sequence offset
    uint32_t ack_number;         ///< TCP acknowledgment offset

    // Payload details
    size_t payload_length;             ///< Size of application payload in bytes
    const uint8_t* payload_data = nullptr; ///< Pointer to start of payload in raw packet buffer
};

/**
 * @brief Parsing logic utility class.
 */
class PacketParser {
public:
    /**
     * @brief Parse a raw captured packet into a structured layout.
     * @return true if parsing succeeded, false if packet is malformed.
     */
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);
    
    /**
     * @brief Convert MAC address bytes into human-readable colon-hex string format.
     */
    [[nodiscard]] static std::string macToString(const uint8_t* mac);

    /**
     * @brief Convert IP integer address into human-readable dotted-decimal string format.
     */
    [[nodiscard]] static std::string ipToString(uint32_t ip);

    /**
     * @brief Convert Layer 4 protocol ID to human-readable string representation.
     */
    [[nodiscard]] static std::string protocolToString(uint8_t protocol);

    /**
     * @brief Convert TCP flags byte to human-readable space-separated string representation.
     */
    [[nodiscard]] static std::string tcpFlagsToString(uint8_t flags);
    
private:
    static bool parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
};

namespace TCPFlags {
    constexpr uint8_t FIN = 0x01; ///< Finish flag
    constexpr uint8_t SYN = 0x02; ///< Synchronize sequence numbers
    constexpr uint8_t RST = 0x04; ///< Reset connection flag
    constexpr uint8_t PSH = 0x08; ///< Push buffered data flag
    constexpr uint8_t ACK = 0x10; ///< Acknowledgment field valid flag
    constexpr uint8_t URG = 0x20; ///< Urgent pointer field valid flag
}

namespace Protocol {
    constexpr uint8_t ICMP = 1;  ///< Internet Control Message Protocol number
    constexpr uint8_t TCP = 6;   ///< Transmission Control Protocol number
    constexpr uint8_t UDP = 17;  ///< User Datagram Protocol number
}

namespace EtherType {
    constexpr uint16_t IPv4 = 0x0800; ///< EtherType value for IPv4 payload
    constexpr uint16_t IPv6 = 0x86DD; ///< EtherType value for IPv6 payload
    constexpr uint16_t ARP  = 0x0806; ///< EtherType value for ARP payload
}

} // namespace PacketAnalyzer

#endif // PACKET_PARSER_H