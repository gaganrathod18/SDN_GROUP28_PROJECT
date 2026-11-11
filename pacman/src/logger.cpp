#include "logger.h"
#include "pacman_types.h"
#include <chrono>
#include <filesystem>

namespace PacMan {

bool Logger::open(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Ensure the parent directory exists before opening the log file
    try {
        const std::filesystem::path log_path(path);
        if (log_path.has_parent_path()) {
            std::filesystem::create_directories(log_path.parent_path());
        }
    } catch (const std::filesystem::filesystem_error&) {
        // Best-effort; continue to attempt file opening even if directory creation fails.
    }
    
    file_.open(path, std::ios::app);
    return file_.is_open();
}

void Logger::info(const std::string& message) {
    write(LogLevel::INFO, message);
}

void Logger::warning(const std::string& message) {
    write(LogLevel::WARNING, message);
}

void Logger::error(const std::string& message) {
    write(LogLevel::ERROR, message);
}

void Logger::write(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!file_.is_open()) {
        return;
    }
    
    file_ << "[" << levelToString(level) << "] "
          << formatTime(std::chrono::system_clock::now()) << " "
          << message << '\n';
    file_.flush();   // keep the log complete even if PacMan is killed by a signal
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::INFO: 
            return "INFO";
        case LogLevel::WARNING: 
            return "WARNING";
        case LogLevel::ERROR: 
            return "ERROR";
    }
    return "INFO";
}

} // namespace PacMan
