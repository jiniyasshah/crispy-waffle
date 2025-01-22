#include "../headers/udp_inspector.h"
#include "../headers/network_uploader.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../headers/utils.h"
#include <sstream>
#include <iomanip>

// QUIC packet types - renamed to avoid conflicts with Windows definitions
enum QuicPacketType {
    QUIC_INITIAL = 0x0,
    QUIC_HANDSHAKE = 0x2,
    QUIC_ZERO_RTT = 0x1,
    QUIC_SHORT_HEADER = 0x3,  // Changed from SHORT to QUIC_SHORT_HEADER
    QUIC_RETRY = 0x4,
    QUIC_VERSION_NEGOTIATION = 0xFF
};

std::string getQuicPacketInfo(const u_char* payload, size_t length) {
    if (length < 1) return "Invalid QUIC packet";
    
    std::stringstream ss;
    uint8_t firstByte = payload[0];
    
    // Check if it's a long header (first bit is 1)
    bool isLongHeader = (firstByte & 0x80) != 0;
    
    if (isLongHeader) {
        // Get packet type from bits 4-5
        uint8_t packetType = (firstByte & 0x30) >> 4;
        
        switch(packetType) {
            case QUIC_INITIAL:
                ss << "Initial";
                break;
            case QUIC_HANDSHAKE:
                ss << "Handshake";
                break;
            case QUIC_ZERO_RTT:
                ss << "0-RTT";
                break;
            case QUIC_RETRY:
                ss << "Retry";
                break;
            default:
                if (firstByte == 0xFF) {
                    ss << "Version Negotiation";
                } else {
                    ss << "Unknown Long Header Type";
                }
        }
    } else {
        ss << "Short Header";
        // For short header packets, try to determine if it's application data
        ss << " (1-RTT)";
    }
    
    return ss.str();
}

std::string getWellKnownUdpPort(unsigned short port) {
    switch(port) {
        case 443: return "QUIC";
        case 53: return "DNS";
        case 67:
        case 68: return "DHCP";
        case 123: return "NTP";
        case 161: return "SNMP";
        case 500: return "IKE";
        default: return std::to_string(port);
    }
}

bool UDPInspector::inspect(const u_char *packet, const struct pcap_pkthdr *header) {
    const IPHeader *ipHeader = reinterpret_cast<const IPHeader*>(packet + ETHERNET_HEADER_SIZE);
    int ipHeaderLength = ipHeader->ihl * 4;
    const UDPHeader *udpHeader = reinterpret_cast<const UDPHeader*>(packet + ETHERNET_HEADER_SIZE + ipHeaderLength);

    // Get source and destination ports
    unsigned short srcPort = ntohs(udpHeader->source);
    unsigned short dstPort = ntohs(udpHeader->dest);

    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(ipHeader->saddr), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->daddr), dstIp, INET_ADDRSTRLEN);
    
    // Calculate UDP payload length
    unsigned short udpLength = ntohs(udpHeader->len);
    int payloadLength = udpLength - sizeof(UDPHeader);
    
    // Get the current timestamp
    std::string timestamp = getCurrentTimestamp();

    // Create info string
    std::stringstream info;
    
    // Point to the UDP payload
    const u_char* payload = packet + ETHERNET_HEADER_SIZE + ipHeaderLength + sizeof(UDPHeader);
    
    // Check if this might be a QUIC packet (typically uses port 443)
    bool isQuic = (srcPort == 443 || dstPort == 443);
    
    if (isQuic && payloadLength > 0) {
        // Get QUIC packet information
        std::string quicInfo = getQuicPacketInfo(payload, payloadLength);
        info << "QUIC: " << quicInfo;
        
        // Add length information
        info << ", len=" << payloadLength;
    } else {
        // For non-QUIC UDP packets
        info << getWellKnownUdpPort(srcPort) << " -> " << getWellKnownUdpPort(dstPort);
        info << " Len=" << payloadLength;
    }



    // Print all details in one line
    std::cout << srcPort << "\t"
              << timestamp << "\t"
              << inet_ntoa(*(in_addr*)&ipHeader->saddr) << "\t"
              << inet_ntoa(*(in_addr*)&ipHeader->daddr) << "\t" 
              << "UDP" << "\t" << " "
              << header->len << "\t"
              << info.str() << "\t"
              << std::endl;


     PacketData packetData{
        srcPort,
       timestamp,  // implement this utility function
       inet_ntoa(*(in_addr*)&ipHeader->saddr),
        inet_ntoa(*(in_addr*)&ipHeader->daddr),
        "UDP",
       header->len,
        info.str(),
        "200 ok",
    };

    auto& uploader = NetworkUploader::getInstance();
    
    // Initialize once (maybe in your main.cpp)
    static bool initialized = false;
    if (!initialized) {
        initialized = uploader.initialize();
        uploader.setServerDetails(L"nids-six.vercel.app", 443, L"/api/pusher");
    }

    // // Upload packet data
    // if (!uploader.uploadPacketData(packetData.toJson())) {
    //     // Handle error - maybe log it
    // }            

    return true;
}