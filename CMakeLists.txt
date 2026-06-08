cmake_minimum_required(VERSION 3.16)
project(FlowSentry VERSION 1.0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# 1. FlowSentry Detailed Viewer
add_executable(flow_sentry
    src/sentry_main.cpp
    src/sentry_pcap_reader.cpp
    src/sentry_packet_parser.cpp
)

# 2. FlowSentry simple DPI Engine
add_executable(flow_sentry_simple
    src/sentry_engine_simple.cpp
    src/sentry_pcap_reader.cpp
    src/sentry_packet_parser.cpp
    src/sentry_sni_extractor.cpp
    src/sentry_types.cpp
)

# 3. FlowSentry quick SNI Inspector
add_executable(flow_sentry_inspector
    src/sentry_inspector_simple.cpp
    src/sentry_pcap_reader.cpp
    src/sentry_packet_parser.cpp
    src/sentry_sni_extractor.cpp
    src/sentry_types.cpp
)
