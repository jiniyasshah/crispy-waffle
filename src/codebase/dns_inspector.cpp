#include "../headers/dns_inspector.h"
#include "../headers/network_uploader.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../headers/utils.h"
#include <sstream>

// Only define DNSQuestion since it's not in the headers
#pragma pack(push, 1)
struct DNSQuestion {
    uint16_t qtype;
    uint16_t qclass;
};
#pragma pack(pop)

bool DNSInspector::inspect(const u_char *packet, const struct pcap_pkthdr *header) {
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

    // Check if this is likely a DNS packet by checking the port numbers
    // DNS typically uses port 53
    if (ntohs(udpHeader->dest) != 53 && ntohs(udpHeader->source) != 53) {
        return false;  // Not a DNS packet
    }

    // Validate packet length
    if (header->len < (ETHERNET_HEADER_SIZE + ipHeaderLength + sizeof(UDPHeader) + sizeof(DNSHeader))) {
        return false;  // Packet too short to be DNS
    }

    const DNSHeader *dnsHeader = reinterpret_cast<const DNSHeader*>((u_char*)udpHeader + sizeof(UDPHeader));

    // Basic DNS header validation
    uint16_t questionCount = ntohs(dnsHeader->qdcount);
    uint16_t answerCount = ntohs(dnsHeader->ancount);
    
    // Validate counts are reasonable
    if (questionCount > 100 || answerCount > 100) {
        return false;  // Likely not a valid DNS packet
    }

    // Get the current timestamp
    std::string timestamp = getCurrentTimestamp();

    // Extract DNS information
    bool isResponse = (ntohs(dnsHeader->flags) & 0x8000) != 0;
    
    // Point to the start of the DNS question section
    const u_char* dnsData = (const u_char*)dnsHeader + sizeof(DNSHeader);
    
    // Parse the domain name
    std::string domainName;
    const u_char* curr = dnsData;
    
    // Safety check to prevent buffer overrun
    size_t maxLen = header->len - (dnsData - packet);
    size_t pos = 0;
    bool validDomain = true;
    
    // Validate domain name format
    while (pos < maxLen && curr[pos] != 0) {
        uint8_t labelLength = curr[pos];
        
        // Check for invalid label length
        if (labelLength > 63) {  // DNS labels are limited to 63 characters
            validDomain = false;
            break;
        }
        
        pos++;
        if (pos + labelLength > maxLen) {
            validDomain = false;
            break;
        }
        
        for (int i = 0; i < labelLength && pos < maxLen; i++) {
            char c = static_cast<char>(curr[pos]);
            // Check for valid domain name characters
            if (!isalnum(c) && c != '-' && c != '.') {
                validDomain = false;
                break;
            }
            domainName += c;
            pos++;
        }
        
        if (!validDomain) break;
        
        if (pos < maxLen && curr[pos] != 0) {
            domainName += ".";
        }
    }

    if (!validDomain) {
        return false;  // Invalid domain name format
    }

    // Format DNS info string
    std::stringstream ss;
    if (isResponse) {
        ss << "Standard query response ";
        if (answerCount > 0) {
            ss << domainName;
        }
    } else {
        ss << "Standard query ";
        if (questionCount > 0) {
            ss << domainName;
        }
    }

    // Print all details in one line
    std::cout << ntohs(dnsHeader->id) << "\t"
              << timestamp << "\t"
              << inet_ntoa(*(in_addr*)&ipHeader->saddr) << "\t"
              << inet_ntoa(*(in_addr*)&ipHeader->daddr) << "\t" 
              << "DNS" << "\t"<< " "
              << header->len << "\t"
              << ss.str() << "\t"
              << std::endl;

      PacketData packetData{
        srcPort,
       timestamp,  // implement this utility function
       inet_ntoa(*(in_addr*)&ipHeader->saddr),
        inet_ntoa(*(in_addr*)&ipHeader->daddr),
        "DNS",
       header->len,
        ss.str(),
        "200 ok",
    };

    auto& uploader = NetworkUploader::getInstance();
    
    // Initialize once (maybe in your main.cpp)
    static bool initialized = false;
    if (!initialized) {
        initialized = uploader.initialize();
        uploader.setServerDetails(L"nids-six.vercel.app", 443, L"/api/pusher");
    }

    // Upload packet data
    if (!uploader.uploadPacketData(packetData.toJson())) {
        // Handle error - maybe log it
    }            
         

    return true;
}