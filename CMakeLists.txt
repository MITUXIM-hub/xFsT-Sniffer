cmake_minimum_required(VERSION 3.16)
project(xFsT_Sniffer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    set(PLATFORM_WINDOWS TRUE)
    if(NOT DEFINED NPCAP_SDK_PATH)
        set(NPCAP_SDK_PATH "C:/npcap-sdk" CACHE PATH "Path to the Npcap SDK")
    endif()

    find_library(PCAP_LIBRARY NAMES wpcap PATHS "${NPCAP_SDK_PATH}/Lib/x64" "${NPCAP_SDK_PATH}/Lib")
    find_path(PCAP_INCLUDE_DIR NAMES pcap.h PATHS "${NPCAP_SDK_PATH}/Include")

    if(NOT PCAP_LIBRARY OR NOT PCAP_INCLUDE_DIR)
        message(FATAL_ERROR "Npcap SDK not found. Set NPCAP_SDK_PATH to the installed SDK directory.")
    endif()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
endif()

add_executable(xFsT-Sniffer src/xFsT_Sniffer.cpp)

if(WIN32)
    target_include_directories(xFsT-Sniffer PRIVATE "${PCAP_INCLUDE_DIR}")
    target_link_libraries(xFsT-Sniffer PRIVATE "${PCAP_LIBRARY}" ws2_32 iphlpapi)
else()
    target_include_directories(xFsT-Sniffer PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(xFsT-Sniffer PRIVATE ${PCAP_LIBRARIES})
endif()

target_compile_options(xFsT-Sniffer PRIVATE -Wall -Wextra -O2)
set_target_properties(xFsT-Sniffer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
