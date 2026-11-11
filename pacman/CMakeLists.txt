cmake_minimum_required(VERSION 3.16)
project(PacMan VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Compiler flags
# ---------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O2)
    endif()
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(CURL QUIET)
include(FetchContent)

# FTXUI — try installed package first, then fetch from GitHub.
find_package(ftxui CONFIG QUIET)
if(NOT ftxui_FOUND)
    message(STATUS "FTXUI not found locally — fetching from GitHub…")
    FetchContent_Declare(
        ftxui
        GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
        GIT_TAG        v5.0.0
        GIT_SHALLOW    TRUE       # faster clone
    )
    FetchContent_MakeAvailable(ftxui)
endif()

# libpcap (optional — required only for live capture mode)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h pcap.h)
find_library(PCAP_LIBRARY pcap)

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
include_directories(${CMAKE_SOURCE_DIR}/include)

set(PACMAN_SOURCES
    src/main.cpp
    src/config_manager.cpp
    src/logger.cpp
    src/pacman_types.cpp
    src/shared_statistics.cpp
    src/flow_tracker.cpp
    src/traffic_classifier.cpp
    src/threat_detector.cpp
    src/dashboard.cpp
    src/report_generator.cpp
    src/virus_total_client.cpp
    src/pacman_engine.cpp
    src/firewall_manager.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/ui_components/overview_tab.cpp
    src/ui_components/flows_tab.cpp
    src/ui_components/dnslog_tab.cpp
    src/ui_components/traffic_tab.cpp
    src/ui_components/protocols_tab.cpp
    src/ui_components/endpoints_tab.cpp
    src/ui_components/analytics_tab.cpp
    src/ui_components/help_tab.cpp
    src/ui_components/firewall_tab.cpp
    src/ui_components/ips_tab.cpp
    src/ui_components/ids_tab.cpp
    src/ui_components/crypto_tab.cpp
)

add_executable(pacman ${PACMAN_SOURCES})
target_link_libraries(pacman PRIVATE Threads::Threads)

# ---------------------------------------------------------------------------
# Optional: FTXUI
# ---------------------------------------------------------------------------
set(PACMAN_FTXUI_ENABLED OFF)
if(TARGET ftxui::screen AND TARGET ftxui::dom AND TARGET ftxui::component)
    set(PACMAN_FTXUI_ENABLED ON)
    target_compile_definitions(pacman PRIVATE PACMAN_HAVE_FTXUI)
    target_link_libraries(pacman PRIVATE
        ftxui::screen
        ftxui::dom
        ftxui::component
    )
endif()

# ---------------------------------------------------------------------------
# Optional: libpcap
# ---------------------------------------------------------------------------
if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    target_compile_definitions(pacman PRIVATE PACMAN_HAVE_PCAP)
    target_include_directories(pacman PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(pacman PRIVATE ${PCAP_LIBRARY})
endif()

# ---------------------------------------------------------------------------
# Optional: libcurl (VirusTotal enrichment)
# ---------------------------------------------------------------------------
if(CURL_FOUND)
    target_compile_definitions(pacman PRIVATE PACMAN_HAVE_CURL)
    target_link_libraries(pacman PRIVATE CURL::libcurl)
endif()

# ---------------------------------------------------------------------------
# Status summary
# ---------------------------------------------------------------------------
message(STATUS "---------------------------------------")
message(STATUS " PacMan v${PROJECT_VERSION} build config")
message(STATUS "---------------------------------------")
message(STATUS " Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS " C++ std    : ${CMAKE_CXX_STANDARD}")
message(STATUS " libpcap    : ${PCAP_LIBRARY}")
message(STATUS " libcurl    : ${CURL_FOUND}")
message(STATUS " FTXUI      : ${PACMAN_FTXUI_ENABLED}")
message(STATUS "---------------------------------------")

# ---------------------------------------------------------------------------
# Packaging (CPack)
# ---------------------------------------------------------------------------
install(TARGETS pacman DESTINATION bin)

set(CPACK_PACKAGE_NAME "pacman-monitor")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "PacMan: Terminal-based Network Security Monitor")
set(CPACK_PACKAGE_VENDOR "Gagan Rathod")
set(CPACK_PACKAGE_CONTACT "gaganrathod18@example.com")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr/local")

# DEB Config
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libpcap0.8, libcurl4")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Gagan Rathod")

# RPM Config
set(CPACK_RPM_PACKAGE_ARCHITECTURE "x86_64")
set(CPACK_RPM_PACKAGE_REQUIRES "libpcap, libcurl")

set(CPACK_GENERATOR "DEB;RPM")
include(CPack)
