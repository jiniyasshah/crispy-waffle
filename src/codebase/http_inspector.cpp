#include "../headers/http_inspector.h"
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
          << ntohs(tcpHeader->source) << "\t"
          << timestamp << "\t"
          << inet_ntoa(*(in_addr*)&ipHeader->saddr) << "\t"
          << inet_ntoa(*(in_addr*)&ipHeader->daddr) << "\t" 
          << "HTTP" << "\t" << " "
          << header->len << "\t" 
          << httpRequestLine << "\t"
          << (!result.empty() ? "MALICIOUS: " + result : "")
          << (result.empty() ? "" : "\033[0m")  // Reset color if malicious
          << std::endl;

            return true; // Indicate that this is an HTTP packet
        }
    }
    return false; // Not an HTTP packet
}
