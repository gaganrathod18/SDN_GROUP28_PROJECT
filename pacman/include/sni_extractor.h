#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <string>
#include <cstdint>
#include <optional>
#include <vector>

namespace DPI {

/**
 * @brief Extracted information from the TLS client handshake sequence.
 */
struct TLSHandshakeInfo {
    std::string version = "—";          ///< Detected TLS protocol version (e.g. "TLS 1.2", "TLS 1.3")
    std::string cipher_suite = "—";     ///< Preferred cipher suite name
    std::string ja3_fingerprint = "—";  ///< Calculated JA3 fingerprint string representation
};

/**
 * @brief Deep Packet Inspection utility for extracting Server Name Indication (SNI) hostnames from TLS handshakes.
 */
class SNIExtractor {
public:
    /**
     * @brief Extract SNI hostname from a raw TCP payload stream.
     * @param payload Pointer to start of TCP payload.
     * @param length Total length of TCP payload in bytes.
     * @return The SNI domain name if extracted, otherwise std::nullopt.
     */
    [[nodiscard]] static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    
    /**
     * @brief Check if TCP payload data matches a standard TLS Client Hello signature.
     */
    [[nodiscard]] static bool isTLSClientHello(const uint8_t* payload, size_t length);
    
    /**
     * @brief Extract parsed extension types from TLS Client Hello for debug/logging.
     */
    [[nodiscard]] static std::vector<std::pair<uint16_t, std::string>> extractExtensions(
        const uint8_t* payload, size_t length);

    /**
     * @brief Parse raw TLS payload to retrieve cryptographic handshake metadata details.
     */
    [[nodiscard]] static std::optional<TLSHandshakeInfo> parseHandshake(const uint8_t* payload, size_t length);

private:
    static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16; ///< TLS content handshake record type
    static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01; ///< Handshake Client Hello subtype
    static constexpr uint16_t EXTENSION_SNI = 0x0000;       ///< SNI extension type identifier
    static constexpr uint8_t SNI_TYPE_HOSTNAME = 0x00;      ///< SNI list entry type for domain hostnames
    
    /**
     * @brief Helper to read 16-bit unsigned integers from big-endian binary payload.
     */
    [[nodiscard]] static uint16_t readUint16BE(const uint8_t* data);

    /**
     * @brief Helper to read 24-bit unsigned integers from big-endian binary payload.
     */
    [[nodiscard]] static uint32_t readUint24BE(const uint8_t* data);
};

/**
 * @brief Simple deep packet inspection logic for parsing QUIC protocol Initial frames (HTTP/3).
 */
class QUICSNIExtractor {
public:
    /**
     * @brief Attempt to extract SNI server name from a QUIC initial frame payload.
     */
    [[nodiscard]] static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    
    /**
     * @brief Validate if the raw payload resembles a QUIC Initial packet stream structure.
     */
    [[nodiscard]] static bool isQUICInitial(const uint8_t* payload, size_t length);
};

/**
 * @brief Deep packet inspection logic for parsing plain-text HTTP Host header values.
 */
class HTTPHostExtractor {
public:
    /**
     * @brief Extract HTTP Host header field value from raw TCP stream payload.
     */
    [[nodiscard]] static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    
    /**
     * @brief Check if TCP payload data starts with common HTTP request method verbs.
     */
    [[nodiscard]] static bool isHTTPRequest(const uint8_t* payload, size_t length);
};

/**
 * @brief Deep packet inspection utility for extracting Domain Name System queries.
 */
class DNSExtractor {
public:
    /**
     * @brief Parse a DNS query frame payload to retrieve the domain name queried.
     */
    [[nodiscard]] static std::optional<std::string> extractQuery(const uint8_t* payload, size_t length);
    
    /**
     * @brief Check if UDP payload corresponds to a DNS query transmission (not response).
     */
    [[nodiscard]] static bool isDNSQuery(const uint8_t* payload, size_t length);
};

} // namespace DPI

#endif // SNI_EXTRACTOR_H