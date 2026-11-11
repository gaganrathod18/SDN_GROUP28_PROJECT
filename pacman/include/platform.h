#ifndef PLATFORM_H
#define PLATFORM_H

// Platform-specific includes and definitions for cross-platform compatibility
// This header provides portable byte-order conversion functions

#include <cstdint>

// Portable byte order conversion namespace
// Works on any platform without requiring platform-specific system headers
namespace PortableNet {

/**
 * @brief Swaps the byte order of a 16-bit unsigned integer.
 * e.g., converts 0x1234 to 0x3412.
 */
[[nodiscard]] inline uint16_t swapBytes16(uint16_t value) {
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

/**
 * @brief Swaps the byte order of a 32-bit unsigned integer.
 * e.g., converts 0x12345678 to 0x78563412.
 */
[[nodiscard]] inline uint32_t swapBytes32(uint32_t value) {
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x000000FF) << 24);
}

/**
 * @brief Check system endianness at runtime.
 * Returns true if the system architecture is Little Endian.
 */
[[nodiscard]] inline bool isLittleEndian() {
    uint16_t test_integer = 0x0001;
    // Examine the first memory byte of the 16-bit integer.
    // If it's 0x01, the least significant byte is stored first (Little Endian).
    return *reinterpret_cast<uint8_t*>(&test_integer) == 0x01;
}

/**
 * @brief Convert 16-bit network byte order (big-endian) to host byte order.
 */
[[nodiscard]] inline uint16_t netToHost16(uint16_t netValue) {
    if (isLittleEndian()) {
        return swapBytes16(netValue);
    }
    return netValue;
}

/**
 * @brief Convert 32-bit network byte order (big-endian) to host byte order.
 */
[[nodiscard]] inline uint32_t netToHost32(uint32_t netValue) {
    if (isLittleEndian()) {
        return swapBytes32(netValue);
    }
    return netValue;
}

/**
 * @brief Convert 16-bit host byte order to network byte order.
 */
[[nodiscard]] inline uint16_t hostToNet16(uint16_t hostValue) {
    return netToHost16(hostValue);  // Reversible operation
}

/**
 * @brief Convert 32-bit host byte order to network byte order.
 */
[[nodiscard]] inline uint32_t hostToNet32(uint32_t hostValue) {
    return netToHost32(hostValue);  // Reversible operation
}

} // namespace PortableNet

#endif // PLATFORM_H