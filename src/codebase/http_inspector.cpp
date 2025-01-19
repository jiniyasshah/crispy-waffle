#include "../headers/http_inspector.h"
#include "../headers/network_uploader.h"
#include "../headers/base64_encoder.h"
#include <iostream>
#include <cstring>
#include "../headers/utils.h"

HTTPInspector::HTTPInspector() : initialized(false) {
    initializeRules();
}

void HTTPInspector::initializeRules() {
    if (!initialized) {
        if (ruleEngine.loadRules("rules/sample.rules")) {
            initialized = true;
        } else {
            std::cerr << "HTTP Inspector: Failed to load rules" << std::endl;
        }
    }
}

bool HTTPInspector::inspect(const u_char *packet, const struct pcap_pkthdr *header) {
    const IPHeader *ipHeader = reinterpret_cast<const IPHeader*>(packet + ETHERNET_HEADER_SIZE);
    int ipHeaderLength = ipHeader->ihl * 4;
    const TCPHeader *tcpHeader = reinterpret_cast<const TCPHeader*>(packet + ETHERNET_HEADER_SIZE + ipHeaderLength);
    int tcpHeaderLength = tcpHeader->doff * 4;
        // Get source and destination ports
    unsigned short srcPort = ntohs(tcpHeader->source);
    unsigned short dstPort = ntohs(tcpHeader->dest);
    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(ipHeader->saddr), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->daddr), dstIp, INET_ADDRSTRLEN);


    auto& processManager = ProcessManager::getInstance();
    DWORD pid = processManager.getProcessIdForConnection(srcIp, srcPort, dstIp, dstPort);
    
    // Get current process ID from the manager
    DWORD currentPid = processManager.getCurrentProcessId();
    
    if (pid == currentPid || pid == 0) {
        return true;
    }
    // Calculate the TCP payload offset
    const u_char *payload = packet + ETHERNET_HEADER_SIZE + ipHeaderLength + tcpHeaderLength;
    unsigned int payloadLen = header->caplen - (ETHERNET_HEADER_SIZE + ipHeaderLength + tcpHeaderLength);

    // Check if payload length is greater than 0 and contains HTTP data
    if (payloadLen > 0) {
        std::string payloadStr(reinterpret_cast<const char*>(payload), payloadLen);
        if (payloadStr.find("HTTP/1.") != std::string::npos || payloadStr.find("GET ") == 0 || payloadStr.find("POST ") == 0) {
            std::string httpRequestLine = payloadStr.substr(0, payloadStr.find("\r\n"));
            std::string encodedData = base64_encode(payloadStr);

            // Check if malicious after converting to string
            std::string result = ruleEngine.match(payloadStr);

            // Get the current timestamp
            std::string timestamp = getCurrentTimestamp();

            // Print all details in one line
 std::cout << (result.empty() ? "" : "\033[1;31m")  // Start red color if malicious
          << pid << "\t"
          << timestamp << "\t"
          << inet_ntoa(*(in_addr*)&ipHeader->saddr) << "\t"
          << inet_ntoa(*(in_addr*)&ipHeader->daddr) << "\t" 
          << "HTTP" << "\t" << " "
          << header->len << "\t" 
          << httpRequestLine << "\t"
          << (!result.empty() ? "MALICIOUS: " + result : "")
          << (result.empty() ? "" : "\033[0m")  // Reset color if malicious
          << std::endl;

       PacketData packetData{
        srcPort,
       timestamp,  // implement this utility function
       inet_ntoa(*(in_addr*)&ipHeader->saddr),
        inet_ntoa(*(in_addr*)&ipHeader->daddr),
        "HTTP",
       header->len,
        httpRequestLine,
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

            return true; // Indicate that this is an HTTP packet
        }
    }
    return false; // Not an HTTP packet
}
