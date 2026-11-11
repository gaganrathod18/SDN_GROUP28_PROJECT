#include "config_manager.h"
#include "pacman_engine.h"
#include <iostream>
#include <cstdlib>
#include <vector>
#include <string>

#if defined(PACMAN_HAVE_PCAP)
#include <pcap/pcap.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#endif

namespace {

// ANSI Color Codes
#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_DIM     "\033[2m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_BCYAN   "\033[96m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_BGREEN  "\033[92m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_RED     "\033[31m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_WHITE   "\033[97m"
#define ANSI_GRAY    "\033[90m"

/**
 * @brief Prints the command line usage for the application.
 */
void printUsage() {
    std::cout << ANSI_BOLD << ANSI_CYAN << "PacMan - Packet Analysis & Cyber Monitoring" << ANSI_RESET << "\n\n";
    std::cout << ANSI_BOLD << "Usage:" << ANSI_RESET << "\n";
    std::cout << "  " << ANSI_GREEN << "pacman live [config/pacman.conf] [--iface NAME]" << ANSI_RESET << "\n";
    std::cout << "  " << ANSI_GREEN << "pacman analyze <file.pcap> [config/pacman.conf]" << ANSI_RESET << "\n";
}

#if defined(PACMAN_HAVE_PCAP)
/**
 * @brief Retrieves the IPv4 address for a given interface name from the OS at runtime.
 * @param iface_name The name of the interface.
 * @return The IP address as a string, or empty string if not found.
 */
std::string getInterfaceIP(const std::string& iface_name) {
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) return "";
    std::string ip;
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_name != iface_name) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            char buf[INET_ADDRSTRLEN];
            void* addr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, addr, buf, sizeof(buf));
            ip = buf;
            break;
        }
    }
    freeifaddrs(ifaddr);
    return ip;
}

/**
 * @brief Checks whether an interface is UP and RUNNING via its flags.
 * @param iface_name The name of the interface.
 * @return True if up, false otherwise.
 */
bool isInterfaceUp(const std::string& iface_name) {
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) return false;
    bool up = false;
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == iface_name) {
            up = (ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING);
            break;
        }
    }
    freeifaddrs(ifaddr);
    return up;
}

/**
 * @brief Checks if the given interface is a loopback interface.
 * @param iface_name The name of the interface.
 * @return True if loopback, false otherwise.
 */
bool isLoopback(const std::string& iface_name) {
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) return false;
    bool lo = false;
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == iface_name) {
            lo = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
            break;
        }
    }
    freeifaddrs(ifaddr);
    return lo;
}
#endif

/**
 * @brief Prompts the user to select an interface interactively via standard input.
 * @return The selected interface name.
 */
std::string selectInterface() {
#if defined(PACMAN_HAVE_PCAP)
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << ANSI_RED << "Warning: Could not enumerate network devices: " << errbuf << ANSI_RESET << "\n";
        return "any";
    }

    struct IfEntry {
        std::string name;
        std::string ip;
        bool up;
        bool loopback;
    };

    std::vector<IfEntry> interfaces;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        IfEntry e;
        e.name     = d->name;
        e.ip       = getInterfaceIP(d->name);
        e.up       = isInterfaceUp(d->name);
        e.loopback = isLoopback(d->name);
        interfaces.push_back(e);
    }

    if (interfaces.empty()) {
        if (alldevs) pcap_freealldevs(alldevs);
        return "any";
    }

    // ── Banner ────────────────────────────────────────────────────────────────
    std::cout << "\n";
    std::cout << ANSI_BOLD << ANSI_CYAN
              << "  ╔══════════════════════════════════════════════╗\n"
              << "  ║    PacMan — Network Interface Selector       ║\n"
              << "  ╚══════════════════════════════════════════════╝\n"
              << ANSI_RESET;
    std::cout << ANSI_GRAY
              << "  Interfaces are queried live from your device.\n"
              << "  Choose the interface you want to capture on.\n"
              << ANSI_RESET << "\n";

    // ── Column headers ────────────────────────────────────────────────────────
    std::cout << ANSI_BOLD << ANSI_GRAY
              << "   #   INTERFACE       STATUS     IP ADDRESS        TYPE\n"
              << "  ─────────────────────────────────────────────────────────\n"
              << ANSI_RESET;

    // ── Interface rows ────────────────────────────────────────────────────────
    for (size_t i = 0; i < interfaces.size(); ++i) {
        const IfEntry& e = interfaces[i];

        // Index
        std::cout << "  [" << ANSI_BGREEN << ANSI_BOLD << (i + 1) << ANSI_RESET << "]  ";

        // Interface name (padded to 15 chars)
        std::string padded_name = e.name;
        while (padded_name.size() < 15) padded_name += ' ';
        std::cout << ANSI_BOLD << ANSI_WHITE << padded_name << ANSI_RESET << "  ";

        // UP/DOWN status
        if (!e.up) {
            std::cout << ANSI_RED << ANSI_BOLD << "DOWN       " << ANSI_RESET;
        } else {
            std::cout << ANSI_BGREEN << ANSI_BOLD << "UP         " << ANSI_RESET;
        }

        // IP Address (padded)
        std::string ip_display = e.ip.empty() ? "No IP" : e.ip;
        while (ip_display.size() < 17) ip_display += ' ';
        std::cout << ANSI_YELLOW << ip_display << ANSI_RESET << "  ";

        // Type badge
        if (e.loopback) {
            std::cout << ANSI_GRAY << "[loopback]" << ANSI_RESET;
        } else if (e.name.find("wl") == 0 || e.name.find("wlan") == 0) {
            std::cout << ANSI_CYAN << "[wifi]" << ANSI_RESET;
        } else if (e.name.find("eth") == 0 || e.name.find("en") == 0) {
            std::cout << ANSI_GREEN << "[ethernet]" << ANSI_RESET;
        } else if (e.name == "any") {
            std::cout << ANSI_MAGENTA << "[all interfaces]" << ANSI_RESET;
        } else {
            std::cout << ANSI_GRAY << "[other]" << ANSI_RESET;
        }

        std::cout << "\n";
    }

    // Custom entry option
    std::cout << "  [" << ANSI_BGREEN << ANSI_BOLD << (interfaces.size() + 1) << ANSI_RESET << "]  "
              << ANSI_DIM << "Enter custom interface name..." << ANSI_RESET << "\n";

    std::cout << ANSI_BOLD << ANSI_CYAN
              << "  ─────────────────────────────────────────────────────────\n"
              << ANSI_RESET;

    // ── Input ─────────────────────────────────────────────────────────────────
    int choice = 0;
    while (true) {
        std::cout << ANSI_BOLD << "\n  Enter selection (1-" << (interfaces.size() + 1) << "): " << ANSI_RESET;
        if (std::cin >> choice && choice >= 1 && choice <= static_cast<int>(interfaces.size() + 1)) {
            break;
        }
        std::cin.clear();
        std::cin.ignore(10000, '\n');
        std::cout << ANSI_RED << "  Invalid choice. Please try again.\n" << ANSI_RESET;
    }

    std::string selected_iface;
    if (choice == static_cast<int>(interfaces.size() + 1)) {
        std::cout << ANSI_BOLD << "  Enter custom interface name: " << ANSI_RESET;
        std::cin >> selected_iface;
    } else {
        selected_iface = interfaces[static_cast<size_t>(choice - 1)].name;
    }

    pcap_freealldevs(alldevs);

    std::cout << "\n  " << ANSI_BGREEN << ANSI_BOLD << "✔ " << ANSI_RESET
              << "Starting capture on: " << ANSI_BOLD << ANSI_CYAN << selected_iface
              << ANSI_RESET << "\n\n";
    return selected_iface;
#else
    return "any";
#endif
}

} // namespace

int main(int argc, char** argv) {
    setenv("SHLVL", "1", 1);

    // Pull out "--iface NAME" so the remaining arguments keep their positions.
    std::string iface_override;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--iface") {
            if (i + 1 >= argc) { printUsage(); return 1; }
            iface_override = argv[++i];
        } else {
            args.push_back(arg);
        }
    }

    if (args.empty()) {
        printUsage();
        return 1;
    }

    const std::string mode = args[0];
    std::string config_path = "config/pacman.conf";
    std::string pcap_path;

    if (mode == "live") {
        if (args.size() >= 2) config_path = args[1];
    } else if (mode == "analyze") {
        if (args.size() < 2) { printUsage(); return 1; }
        pcap_path = args[1];
        if (args.size() >= 3) config_path = args[2];
    } else {
        printUsage();
        return 1;
    }

    PacMan::ConfigManager config_manager;
    if (!config_manager.load(config_path)) {
        std::cerr << ANSI_YELLOW << "Warning: could not load " << config_path
                  << ", using defaults.\n" << ANSI_RESET;
    }

    PacMan::Config config = config_manager.config();

    if (mode == "live") {
        config.interface_name = iface_override.empty() ? selectInterface() : iface_override;
    }

    PacMan::PacManEngine engine(config);
    if (mode == "live") return engine.runLive();
    return engine.analyzeFile(pcap_path);
}
