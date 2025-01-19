cmake_minimum_required(VERSION 3.15)
project(NIDS)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include directories for Npcap
include_directories("C:/Npcap/Include")

# Link directories for Npcap
link_directories("C:/Npcap/Lib")

# Add source files
set(SOURCES
    src/main.cpp
    src/codebase/rule_engine.cpp
    src/codebase/packet_inspector.cpp
    src/codebase/base64_encoder.cpp
    src/codebase/tcp_inspector.cpp
    src/codebase/udp_inspector.cpp
    src/codebase/dns_inspector.cpp
    src/codebase/http_inspector.cpp
    src/codebase/network_uploader.cpp
    src/codebase/process_manager.cpp
    src/codebase/utils.cpp
)

# Include project directories
include_directories(src)

# Create the executable
add_executable(NIDS ${SOURCES})

# Link against the required Npcap, Windows, and WinHTTP libraries
target_link_libraries(NIDS Packet Wpcap winhttp Ws2_32)