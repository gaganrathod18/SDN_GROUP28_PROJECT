#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

namespace PacketAnalyzer {

/**
 * @brief PCAP Global Header struct (exactly 24 bytes).
 * Located at the beginning of every valid .pcap format file.
 */
struct PcapGlobalHeader {
    uint32_t magic_number;   ///< Magic identifier (0xa1b2c3d4 or swapped 0xd4c3b2a1)
    uint16_t version_major;  ///< Major version number (usually 2)
    uint16_t version_minor;  ///< Minor version number (usually 4)
    int32_t  thiszone;       ///< GMT-to-local timezone correction offset in seconds
    uint32_t sigfigs;        ///< Accuracy of timestamps (almost always 0)
    uint32_t snaplen;        ///< Maximum length limit of captured packets in bytes
    uint32_t network;        ///< Link-layer header type (1 = Ethernet)
};

/**
 * @brief PCAP Packet Record Header struct (exactly 16 bytes).
 * Precedes the raw frame bytes of every packet record in the file.
 */
struct PcapPacketHeader {
    uint32_t ts_sec;         ///< Unix epoch timestamp seconds
    uint32_t ts_usec;        ///< Microseconds fractional part of timestamp
    uint32_t incl_len;       ///< Frame segment size stored in the file (captured size)
    uint32_t orig_len;       ///< Actual original frame length on the wire
};

/**
 * @brief A container wrapping a captured raw packet's header and data bytes.
 */
struct RawPacket {
    PcapPacketHeader header;    ///< Meta-information about the packet record
    std::vector<uint8_t> data;  ///< Raw packet binary bytes
};

/**
 * @brief Native reader class for .pcap files.
 * Custom implementation that reads PCAP files binary structures without relying on libpcap.
 */
class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader();

    /**
     * @brief Open a PCAP format file.
     * @param filename Path to the PCAP file on the filesystem.
     * @return true if opened and global header validated, false otherwise.
     */
    bool open(const std::string& filename);
    
    /**
     * @brief Close the active file stream.
     */
    void close();
    
    /**
     * @brief Read the next packet record from the file stream.
     * @param packet Reference to receive the parsed packet data.
     * @return true if a packet was read successfully, false on EOF or read failure.
     */
    bool readNextPacket(RawPacket& packet);
    
    /**
     * @brief Access the file's global header details.
     */
    [[nodiscard]] const PcapGlobalHeader& getGlobalHeader() const { return global_header_; }
    
    /**
     * @brief Check if a file stream is open.
     */
    [[nodiscard]] bool isOpen() const { return file_.is_open(); }
    
    /**
     * @brief Check if the file endianness requires swapping values.
     */
    [[nodiscard]] bool needsByteSwap() const { return needs_byte_swap_; }

private:
    std::ifstream file_;                  ///< Input binary file stream
    PcapGlobalHeader global_header_{};    ///< Parsed global header of the PCAP file
    bool needs_byte_swap_ = false;       ///< Flag if file format endianness is opposite of host

    /**
     * @brief Internal helper to byte-swap 16-bit integers conditionally.
     */
    [[nodiscard]] uint16_t maybeSwap16(uint16_t value);

    /**
     * @brief Internal helper to byte-swap 32-bit integers conditionally.
     */
    [[nodiscard]] uint32_t maybeSwap32(uint32_t value);
};

} // namespace PacketAnalyzer

#endif // PCAP_READER_H