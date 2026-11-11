#include "pcap_reader.h"
#include <iostream>
#include <cstring>

namespace PacketAnalyzer {

// Magic numbers for PCAP files
constexpr uint32_t PCAP_MAGIC_NATIVE = 0xa1b2c3d4;  ///< Native byte order magic number
constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1; ///< Swapped byte order magic number

PcapReader::~PcapReader() {
    close();
}

bool PcapReader::open(const std::string& filename) {
    // Close any previously opened file stream first
    close();
    
    // Open in binary mode — crucial for reading raw bytes correctly
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "Error: Could not open file: " << filename << std::endl;
        return false;
    }
    
    // Read the global header (first 24 bytes of the file)
    file_.read(reinterpret_cast<char*>(&global_header_), sizeof(PcapGlobalHeader));
    if (!file_.good()) {
        std::cerr << "Error: Could not read PCAP global header" << std::endl;
        close();
        return false;
    }
    
    // Check the magic number to determine if byte swapping is needed
    if (global_header_.magic_number == PCAP_MAGIC_NATIVE) {
        needs_byte_swap_ = false;
    } else if (global_header_.magic_number == PCAP_MAGIC_SWAPPED) {
        needs_byte_swap_ = true;
        // Swap the header fields we've already read to match host endianness
        global_header_.version_major = maybeSwap16(global_header_.version_major);
        global_header_.version_minor = maybeSwap16(global_header_.version_minor);
        global_header_.snaplen = maybeSwap32(global_header_.snaplen);
        global_header_.network = maybeSwap32(global_header_.network);
    } else {
        std::cerr << "Error: Invalid PCAP magic number: 0x" 
                  << std::hex << global_header_.magic_number << std::dec << std::endl;
        close();
        return false;
    }
    
    return true;
}

void PcapReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
    needs_byte_swap_ = false;
}

bool PcapReader::readNextPacket(RawPacket& packet) {
    if (!file_.is_open()) {
        return false;
    }
    
    // Read the packet header (16 bytes)
    file_.read(reinterpret_cast<char*>(&packet.header), sizeof(PcapPacketHeader));
    if (!file_.good()) {
        // End of file or read error occurred
        return false;
    }
    
    // Swap bytes if needed
    if (needs_byte_swap_) {
        packet.header.ts_sec = maybeSwap32(packet.header.ts_sec);
        packet.header.ts_usec = maybeSwap32(packet.header.ts_usec);
        packet.header.incl_len = maybeSwap32(packet.header.incl_len);
        packet.header.orig_len = maybeSwap32(packet.header.orig_len);
    }
    
    // Sanity check on packet length limits
    if (packet.header.incl_len > global_header_.snaplen || 
        packet.header.incl_len > 65535) {
        std::cerr << "Error: Invalid packet length: " << packet.header.incl_len << std::endl;
        return false;
    }
    
    // Read the packet raw data payload
    packet.data.resize(packet.header.incl_len);
    file_.read(reinterpret_cast<char*>(packet.data.data()), packet.header.incl_len);
    if (!file_.good()) {
        std::cerr << "Error: Could not read packet data" << std::endl;
        return false;
    }
    
    return true;
}

uint16_t PcapReader::maybeSwap16(uint16_t value) {
    if (!needs_byte_swap_) {
        return value;
    }
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

uint32_t PcapReader::maybeSwap32(uint32_t value) {
    if (!needs_byte_swap_) {
        return value;
    }
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x000000FF) << 24);
}

} // namespace PacketAnalyzer