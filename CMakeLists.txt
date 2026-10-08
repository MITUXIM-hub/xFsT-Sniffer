cmake_minimum_required(VERSION 3.16)
project(xFsT-Sniffer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Platform detection
if(WIN32)
    set(PLATFORM_WINDOWS TRUE)
elseif(APPLE)
    set(PLATFORM_MACOS TRUE)
elseif(UNIX AND NOT APPLE)
    set(PLATFORM_LINUX TRUE)
endif()

# Find required packages
find_package(Threads REQUIRED)

# Windows - Npcap
if(PLATFORM_WINDOWS)
    # Check for Npcap SDK
    if(NOT DEFINED NPCAP_SDK_PATH)
        set(NPCAP_SDK_PATH "C:/npcap-sdk" CACHE PATH "Path to Npcap SDK")
    endif()
    
    find_library(PCAP_LIBRARY
        NAMES wpcap
        PATHS "${NPCAP_SDK_PATH}/Lib/x64"
               "${NPCAP_SDK_PATH}/Lib"
    )
    
    find_path(PCAP_INCLUDE_DIR
        NAMES pcap.h
        PATHS "${NPCAP_SDK_PATH}/Include"
    )
endif()

# Linux/macOS - libpcap
if(PLATFORM_LINUX OR PLATFORM_MACOS)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/sniffer.cpp
    src/packet_parser.cpp
    src/packet_filter.cpp
    src/statistics.cpp
    src/export.cpp
)

set(HEADERS
    src/sniffer.h
    src/packet_parser.h
    src/packet_filter.h
    src/statistics.h
    src/export.h
    src/platform.h
)

# Create executable
add_executable(xFsT-Sniffer ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(xFsT-Sniffer PRIVATE Threads::Threads)

if(PLATFORM_WINDOWS)
    target_include_directories(xFsT-Sniffer PRIVATE "${PCAP_INCLUDE_DIR}")
    target_link_libraries(xFsT-Sniffer PRIVATE "${PCAP_LIBRARY}")
    target_link_libraries(xFsT-Sniffer PRIVATE ws2_32 iphlpapi)
elseif(PLATFORM_LINUX OR PLATFORM_MACOS)
    target_link_libraries(xFsT-Sniffer PRIVATE ${PCAP_LIBRARIES})
    target_include_directories(xFsT-Sniffer PRIVATE ${PCAP_INCLUDE_DIRS})
endif()

# Compiler flags
if(MSVC)
    target_compile_options(xFsT-Sniffer PRIVATE /W4 /O2)
else()
    target_compile_options(xFsT-Sniffer PRIVATE -Wall -Wextra -O2)
endif()

# Output directory
set_target_properties(xFsT-Sniffer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Installation
install(TARGETS xFsT-Sniffer DESTINATION bin)
