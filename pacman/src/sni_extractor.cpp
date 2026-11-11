#include "sni_extractor.h"
#include <cstring>
#include <algorithm>

namespace DPI {

// ============================================================================
// TLS SNI Extractor Implementation
// ============================================================================

uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           data[2];
}

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    // Minimum TLS record size: 5 bytes (Record Layer Header) + 4 bytes (Handshake Header) = 9 bytes
    if (length < 9) {
        return false;
    }
    
    // Check TLS record header
    // Byte 0: Content Type (should be 0x16 = Handshake)
    if (payload[0] != CONTENT_TYPE_HANDSHAKE) {
        return false;
    }
    
    // Bytes 1-2: TLS Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
    // We accept 0x0300 (SSL 3.0) through 0x0304 (TLS 1.3)
    const uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) {
        return false;
    }
    
    // Bytes 3-4: Record length
    const uint16_t record_length = readUint16BE(payload + 3);
    if (record_length > length - 5) {
        return false; // Payload is truncated
    }
    
    // Check handshake header (starts at byte 5)
    // Byte 5: Handshake Type (should be 0x01 = Client Hello)
    if (payload[5] != HANDSHAKE_CLIENT_HELLO) {
        return false;
    }
    
    return true;
}

std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) {
        return std::nullopt;
    }
    
    // Skip TLS record header (5 bytes)
    size_t offset = 5;
    
    // Handshake Layer:
    // Byte 0: Handshake type (already verified as Client Hello)
    // Bytes 1-3: Handshake message length
    const uint32_t handshake_length = readUint24BE(payload + offset + 1);
    (void)handshake_length; // Silence unused variable warning
    offset += 4; // Skip Handshake header
    
    // Client Hello body:
    // Bytes 0-1: Client version (skip)
    offset += 2;
    
    // Bytes 2-33: Random (32 bytes) (skip)
    offset += 32;
    
    // Session ID
    if (offset >= length) {
        return std::nullopt;
    }
    const uint8_t session_id_length = payload[offset];
    offset += 1 + session_id_length; // Skip length byte and Session ID
    
    // Cipher suites
    if (offset + 2 > length) {
        return std::nullopt;
    }
    const uint16_t cipher_suites_length = readUint16BE(payload + offset);
    offset += 2 + cipher_suites_length; // Skip length bytes and Cipher Suites list
    
    // Compression methods
    if (offset >= length) {
        return std::nullopt;
    }
    const uint8_t compression_methods_length = payload[offset];
    offset += 1 + compression_methods_length; // Skip length byte and Compression Methods list
    
    // Extensions
    if (offset + 2 > length) {
        return std::nullopt; // No extensions present
    }
    const uint16_t extensions_total_length = readUint16BE(payload + offset);
    offset += 2; // Skip extensions length bytes
    
    size_t extensions_end = offset + extensions_total_length;
    if (extensions_end > length) {
        extensions_end = length;  // Packet might be truncated, try to parse what we have
    }
    
    // Parse individual extensions to find the SNI extension
    while (offset + 4 <= extensions_end) {
        const uint16_t extension_type = readUint16BE(payload + offset);
        const uint16_t extension_length = readUint16BE(payload + offset + 2);
        offset += 4; // Skip extension type and length
        
        if (offset + extension_length > extensions_end) {
            break; // Truncated extension
        }
        
        if (extension_type == EXTENSION_SNI) {
            // Found Server Name Indication (SNI) extension
            // Format:
            //   SNI List Length (2 bytes)
            //   List of Server Names:
            //     SNI Type (1 byte) - 0x00 for hostname
            //     SNI Length (2 bytes)
            //     SNI Value (variable length hostname string)
            
            if (extension_length < 5) {
                break; // Invalid SNI extension length
            }
            
            const uint16_t sni_list_length = readUint16BE(payload + offset);
            if (sni_list_length < 3) {
                break; // Invalid SNI list length
            }
            
            const uint8_t sni_type = payload[offset + 2];
            const uint16_t sni_length = readUint16BE(payload + offset + 3);
            
            if (sni_type != SNI_TYPE_HOSTNAME) {
                break; // Not a hostname SNI
            }
            if (sni_length > extension_length - 5) {
                break; // SNI length exceeds extension bounds
            }
            
            // Extract and return the actual hostname string
            std::string extracted_sni(reinterpret_cast<const char*>(payload + offset + 5), sni_length);
            return extracted_sni;
        }
        
        // Skip to the next extension
        offset += extension_length;
    }
    
    return std::nullopt; // SNI extension not found
}

std::vector<std::pair<uint16_t, std::string>> SNIExtractor::extractExtensions(
    const uint8_t* payload, size_t length) {
    
    std::vector<std::pair<uint16_t, std::string>> extracted_extensions;
    
    // Basic verification and skipping headers (similar to extract)
    if (!isTLSClientHello(payload, length)) {
        return extracted_extensions;
    }
    
    size_t offset = 5; // Skip TLS record header
    offset += 4;       // Skip Handshake header
    offset += 2;       // Skip Client Version
    offset += 32;      // Skip Random
    
    if (offset >= length) return extracted_extensions;
    offset += 1 + payload[offset]; // Skip Session ID
    
    if (offset + 2 > length) return extracted_extensions;
    offset += 2 + readUint16BE(payload + offset); // Skip Cipher Suites
    
    if (offset >= length) return extracted_extensions;
    offset += 1 + payload[offset]; // Skip Compression Methods
    
    if (offset + 2 > length) return extracted_extensions;
    const uint16_t extensions_total_length = readUint16BE(payload + offset);
    offset += 2; // Skip extensions length bytes
    
    size_t extensions_end = offset + extensions_total_length;
    if (extensions_end > length) {
        extensions_end = length;
    }
    
    // Parse all extensions
    while (offset + 4 <= extensions_end) {
        const uint16_t extension_type = readUint16BE(payload + offset);
        const uint16_t extension_length = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (offset + extension_length > extensions_end) {
            break;
        }
        
        std::string ext_data(reinterpret_cast<const char*>(payload + offset), extension_length);
        extracted_extensions.emplace_back(extension_type, ext_data);
        
        offset += extension_length;
    }
    
    return extracted_extensions;
}

// ============================================================================
// HTTP Host Header Extractor Implementation
// ============================================================================

bool HTTPHostExtractor::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (length < 4) {
        return false;
    }
    
    // Check for common HTTP methods at the start of the payload
    const char* valid_methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
    
    for (const char* method : valid_methods) {
        if (std::memcmp(payload, method, 4) == 0) {
            return true;
        }
    }
    
    return false;
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isHTTPRequest(payload, length)) {
        return std::nullopt;
    }
    
    // Search for "Host: " header in the payload
    // const char* host_header_prefix = "Host: "; // unused variable
    const size_t host_header_prefix_len = 6;
    
    for (size_t i = 0; i + host_header_prefix_len < length; ++i) {
        // Case-insensitive check for "host:"
        if ((payload[i] == 'H' || payload[i] == 'h') &&
            (payload[i+1] == 'o' || payload[i+1] == 'O') &&
            (payload[i+2] == 's' || payload[i+2] == 'S') &&
            (payload[i+3] == 't' || payload[i+3] == 'T') &&
            payload[i+4] == ':') {
            
            // Skip "Host:" and any leading whitespace
            size_t start_idx = i + 5;
            while (start_idx < length && (payload[start_idx] == ' ' || payload[start_idx] == '\t')) {
                start_idx++;
            }
            
            // Find end of line (\r or \n)
            size_t end_idx = start_idx;
            while (end_idx < length && payload[end_idx] != '\r' && payload[end_idx] != '\n') {
                end_idx++;
            }
            
            if (end_idx > start_idx) {
                std::string extracted_host(reinterpret_cast<const char*>(payload + start_idx), end_idx - start_idx);
                
                // Remove port number if present (e.g., "example.com:8080" -> "example.com")
                size_t colon_pos = extracted_host.find(':');
                if (colon_pos != std::string::npos) {
                    extracted_host = extracted_host.substr(0, colon_pos);
                }
                
                return extracted_host;
            }
        }
    }
    
    return std::nullopt;
}

// ============================================================================
// DNS Extractor Implementation
// ============================================================================

bool DNSExtractor::isDNSQuery(const uint8_t* payload, size_t length) {
    // Minimum DNS header is 12 bytes
    if (length < 12) {
        return false;
    }
    
    // Check QR bit (byte 2, bit 7) - should be 0 for a query
    const uint8_t flags = payload[2];
    if (flags & 0x80) {
        return false;  // This is a response, not a query
    }
    
    // Check QDCOUNT (bytes 4-5) - number of questions should be > 0
    const uint16_t question_count = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    if (question_count == 0) {
        return false;
    }
    
    return true;
}

std::optional<std::string> DNSExtractor::extractQuery(const uint8_t* payload, size_t length) {
    if (!isDNSQuery(payload, length)) {
        return std::nullopt;
    }
    
    // DNS queries start immediately after the 12-byte header
    size_t offset = 12;
    std::string extracted_domain;
    
    // Parse the QNAME sequence (series of labels)
    while (offset < length) {
        const uint8_t label_length = payload[offset];
        
        if (label_length == 0) {
            // Null label signifies the end of the domain name
            break;
        }
        
        if (label_length > 63) {
            // Length > 63 indicates a compression pointer or invalid data
            // For simple parsing, we stop here. True DNS parsers would follow the pointer.
            break;
        }
        
        offset++; // Move past the length byte
        if (offset + label_length > length) {
            break; // Truncated label
        }
        
        // Append the label to the domain string
        if (!extracted_domain.empty()) {
            extracted_domain += '.';
        }
        extracted_domain += std::string(reinterpret_cast<const char*>(payload + offset), label_length);
        offset += label_length;
    }
    
    return extracted_domain.empty() ? std::nullopt : std::optional<std::string>(extracted_domain);
}

// ============================================================================
// QUIC SNI Extractor (simplified)
// ============================================================================

bool QUICSNIExtractor::isQUICInitial(const uint8_t* payload, size_t length) {
    if (length < 5) {
        return false;
    }
    
    // QUIC long header format: first bit (form bit) must be set (1)
    const uint8_t first_byte = payload[0];
    
    // Check Long Header form bit (0x80)
    if ((first_byte & 0x80) == 0) {
        return false;
    }
    
    // Could further validate QUIC version (bytes 1-4) here if necessary
    
    return true;
}

std::optional<std::string> QUICSNIExtractor::extract(const uint8_t* payload, size_t length) {
    // QUIC Initial packets contain TLS Client Hello data inside CRYPTO frames.
    // Proper parsing requires full QUIC framing logic.
    // For this simple implementation, we scan the payload for the TLS Client Hello handshake type (0x01).
    
    if (!isQUICInitial(payload, length)) {
        return std::nullopt;
    }
    
    // Scan for TLS Client Hello Handshake Type (0x01)
    for (size_t i = 0; i + 50 < length; ++i) {
        if (payload[i] == 0x01) {  // Client Hello handshake type candidate
            // Try to extract SNI treating this position as the Handshake Type byte
            // SNIExtractor::extract expects the full TLS Record Header, so we provide an offset
            // However, QUIC encapsulates the Handshake directly without the TLS Record Layer.
            // A more robust implementation would construct a dummy Record Header or bypass it.
            // For now, we reuse the existing extractor with an offset adjustment.
            if (i >= 5) {
               auto result = SNIExtractor::extract(payload + i - 5, length - i + 5);
               if (result) return result;
            }
        }
    }
    
    return std::nullopt;
}

std::optional<TLSHandshakeInfo> SNIExtractor::parseHandshake(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) {
        return std::nullopt;
    }
    
    TLSHandshakeInfo parsed_info;
    size_t offset = 5; // Skip TLS Record Header
    
    if (offset + 4 > length) return std::nullopt;
    // const uint32_t handshake_length = readUint24BE(payload + offset + 1);
    offset += 4; // Skip Handshake header
    
    if (offset + 2 > length) return std::nullopt;
    const uint16_t client_hello_ver = readUint16BE(payload + offset);
    offset += 2; // Skip Client Version
    
    if (offset + 32 > length) return std::nullopt;
    offset += 32; // Skip Random bytes
    
    if (offset + 1 > length) return std::nullopt;
    const uint8_t session_id_length = payload[offset];
    offset += 1;
    
    if (offset + session_id_length > length) return std::nullopt;
    offset += session_id_length; // Skip Session ID
    
    if (offset + 2 > length) return std::nullopt;
    const uint16_t cipher_suites_length = readUint16BE(payload + offset);
    offset += 2;
    
    if (offset + cipher_suites_length > length) return std::nullopt;
    
    std::vector<uint16_t> raw_ciphers;
    // Parse cipher suites, ignoring GREASE values (0x?A?A)
    for (size_t c = 0; c + 2 <= cipher_suites_length; c += 2) {
        const uint16_t suite = readUint16BE(payload + offset + c);
        if ((suite & 0x0f0f) != 0x0a0a) { // Ignore GREASE
            raw_ciphers.push_back(suite);
        }
    }
    offset += cipher_suites_length;
    
    if (offset + 1 > length) return std::nullopt;
    const uint8_t compression_methods_length = payload[offset];
    offset += 1;
    
    if (offset + compression_methods_length > length) return std::nullopt;
    offset += compression_methods_length; // Skip Compression Methods
    
    if (offset + 2 > length) return std::nullopt;
    const uint16_t extensions_length = readUint16BE(payload + offset);
    offset += 2;
    
    size_t extensions_end = offset + extensions_length;
    if (extensions_end > length) {
        extensions_end = length;
    }
    
    std::vector<uint16_t> extension_types;
    std::vector<uint16_t> supported_groups;
    std::vector<uint8_t> ec_formats;
    bool has_tls13 = false;
    
    // Parse Extensions for JA3 fingerprinting data
    while (offset + 4 <= extensions_end) {
        const uint16_t ext_type = readUint16BE(payload + offset);
        const uint16_t ext_length = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (offset + ext_length > extensions_end) {
            break; // Truncated extension
        }
        
        if ((ext_type & 0x0f0f) != 0x0a0a) { // Ignore GREASE extension types
            extension_types.push_back(ext_type);
        }
        
        if (ext_type == 0x000a) { // Supported Groups Extension
            if (ext_length >= 2) {
                const uint16_t groups_len = readUint16BE(payload + offset);
                for (size_t g = 2; g + 2 <= static_cast<size_t>(groups_len) + 2 && g + 2 <= ext_length; g += 2) {
                    const uint16_t grp = readUint16BE(payload + offset + g);
                    if ((grp & 0x0f0f) != 0x0a0a) { // Ignore GREASE
                        supported_groups.push_back(grp);
                    }
                }
            }
        } else if (ext_type == 0x000b) { // EC Point Formats Extension
            if (ext_length >= 1) {
                const uint8_t formats_len = payload[offset];
                for (size_t f = 1; f <= static_cast<size_t>(formats_len) && f < ext_length; ++f) {
                    ec_formats.push_back(payload[offset + f]);
                }
            }
        } else if (ext_type == 0x002b) { // Supported Versions Extension (TLS 1.3 indicator)
            if (ext_length >= 1) {
                const uint8_t versions_len = payload[offset];
                for (size_t v = 1; v + 2 <= static_cast<size_t>(versions_len) + 1 && v + 2 <= ext_length; v += 2) {
                    const uint16_t ver = readUint16BE(payload + offset + v);
                    if (ver == 0x0304) { // TLS 1.3 Draft or Final
                        has_tls13 = true;
                    }
                }
            }
        }
        
        offset += ext_length;
    }
    
    // Map common cipher suite hex values to human-readable names
    parsed_info.cipher_suite = "Unknown Cipher";
    for (const uint16_t suite : raw_ciphers) {
        if (suite == 0x1302) { parsed_info.cipher_suite = "TLS_AES_256_GCM_SHA384"; break; }
        if (suite == 0x1301) { parsed_info.cipher_suite = "TLS_AES_128_GCM_SHA256"; break; }
        if (suite == 0x1303) { parsed_info.cipher_suite = "TLS_CHACHA20_POLY1305_SHA256"; break; }
        if (suite == 0xc02b) { parsed_info.cipher_suite = "ECDHE-ECDSA-AES128-GCM-SHA256"; break; }
        if (suite == 0xc02f) { parsed_info.cipher_suite = "ECDHE-RSA-AES128-GCM-SHA256"; break; }
        if (suite == 0xc030) { parsed_info.cipher_suite = "ECDHE-RSA-AES256-GCM-SHA384"; break; }
    }
    if (parsed_info.cipher_suite == "Unknown Cipher" && !raw_ciphers.empty()) {
        char hex_buf[16];
        snprintf(hex_buf, sizeof(hex_buf), "0x%04X", raw_ciphers[0]);
        parsed_info.cipher_suite = hex_buf;
    }
    
    // Determine TLS Version
    parsed_info.version = has_tls13 ? "TLS 1.3" : (client_hello_ver == 0x0303 ? "TLS 1.2" : "TLS 1.1");
    
    // Construct JA3 Fingerprint String (ClientVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats)
    std::string ja3_string;
    ja3_string += std::to_string(client_hello_ver) + ",";
    for (size_t i = 0; i < raw_ciphers.size(); ++i) {
        ja3_string += std::to_string(raw_ciphers[i]) + (i + 1 < raw_ciphers.size() ? "-" : "");
    }
    ja3_string += ",";
    for (size_t i = 0; i < extension_types.size(); ++i) {
        ja3_string += std::to_string(extension_types[i]) + (i + 1 < extension_types.size() ? "-" : "");
    }
    ja3_string += ",";
    for (size_t i = 0; i < supported_groups.size(); ++i) {
        ja3_string += std::to_string(supported_groups[i]) + (i + 1 < supported_groups.size() ? "-" : "");
    }
    ja3_string += ",";
    for (size_t i = 0; i < ec_formats.size(); ++i) {
        ja3_string += std::to_string(ec_formats[i]) + (i + 1 < ec_formats.size() ? "-" : "");
    }
    
    parsed_info.ja3_fingerprint = ja3_string;
    return parsed_info;
}

} // namespace DPI