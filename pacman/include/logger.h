#ifndef PACMAN_LOGGER_H
#define PACMAN_LOGGER_H

#include <fstream>
#include <mutex>
#include <string>

namespace PacMan {

/**
 * @brief Categorized severity levels for logged messages.
 */
enum class LogLevel {
    INFO,       ///< Informational operational message
    WARNING,    ///< Non-critical alerts or potential issues
    ERROR       ///< Critical failures or errors
};

/**
 * @brief Thread-safe Logger that writes timestamped logs to a target file.
 */
class Logger {
public:
    /**
     * @brief Open or create the target log file.
     * @param path The filesystem path to the log file.
     * @return true if successfully opened, false otherwise.
     */
    bool open(const std::string& path);

    /**
     * @brief Log an informational message.
     */
    void info(const std::string& message);

    /**
     * @brief Log a warning alert message.
     */
    void warning(const std::string& message);

    /**
     * @brief Log a critical error message.
     */
    void error(const std::string& message);

private:
    std::mutex mutex_;      ///< Mutex guarding concurrent file writes
    std::ofstream file_;    ///< File stream of the active log file

    /**
     * @brief Internal helper to write a formatted line to the stream.
     */
    void write(LogLevel level, const std::string& message);

    /**
     * @brief Get string prefix for a LogLevel enum value.
     */
    [[nodiscard]] static std::string levelToString(LogLevel level);
};

} // namespace PacMan

#endif // PACMAN_LOGGER_H
