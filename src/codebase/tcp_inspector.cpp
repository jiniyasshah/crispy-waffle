#include "../headers/tcp_inspector.h"
#include "../headers/network_uploader.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../headers/utils.h"
#include <sstream>
#include <iomanip>

std::string getTCPFlags(unsigned char flags) {
    std::string flagStr;
    
    // TCP Flags checking
    if (flags & 0x01) flagStr += "FIN,";
    if (flags & 0x02) flagStr += "SYN,";
    if (flags & 0x04) flagStr += "RST,";
    if (flags & 0x08) flagStr += "PSH,";
    if (flags & 0x10) flagStr += "ACK,";
    if (flags & 0x20) flagStr += "URG,";
    
    // Remove trailing comma if flags exist
    if (!flagStr.empty()) {
        flagStr.pop_back();  // Remove last comma
    } else {
        flagStr = "None";
    }
    
    return flagStr;
}

std::string getWellKnownPort(unsigned short port) {
    switch(port) {
        case 80: return "HTTP";
        case 443: return "HTTPS";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        default: return std::to_string(port);
    }
}

bool TCPInspector::inspect(const u_char *packet, const struct pcap_pkthdr *header) {
    const IPHeader *ipHeader = reinterpret_cast<const IPHeader*>(packet + ETHERNET_HEADER_SIZE);
    int ipHeaderLength = ipHeader->ihl * 4;
    const TCPHeader *tcpHeader = reinterpret_cast<const TCPHeader*>(packet + ETHERNET_HEADER_SIZE + ipHeaderLength);

    std::string timestamp = getCurrentTimestamp();
    
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
    
    // Determine protocol string based on ports
    std::string protocolStr = "TCP";
    if (srcPort == 443 || dstPort == 443) {
        protocolStr = "TLS";
    }
    
    // Rest of your existing code...
    int tcpHeaderLength = tcpHeader->doff * 4;
    std::string flags = getTCPFlags(tcpHeader->flags);
    int totalLength = ntohs(ipHeader->tot_len);
    int payloadLength = totalLength - ipHeaderLength - tcpHeaderLength;
    
    std::stringstream info;
    
    // Your existing connection type determination...
    if (tcpHeader->flags & 0x02) {
        info << "Connection request [SYN] ";
        info << "Seq=" << ntohl(tcpHeader->seq);
    } else if ((tcpHeader->flags & 0x12) == 0x12) {
        info << "Connection established [SYN, ACK] ";
        info << "Seq=" << ntohl(tcpHeader->seq) << " Ack=" << ntohl(tcpHeader->ack_seq);
    } else if (tcpHeader->flags & 0x01) {
        info << "Connection closing [FIN" << (tcpHeader->flags & 0x10 ? "+ACK] " : "] ");
        info << "Seq=" << ntohl(tcpHeader->seq);
    } else if (tcpHeader->flags & 0x04) {
        info << "Connection reset [RST] ";
        info << "Seq=" << ntohl(tcpHeader->seq);
    } else if (payloadLength > 0) {
        info << getWellKnownPort(srcPort) << " -> " << getWellKnownPort(dstPort);
        info << " [" << flags << "] ";
        info << "Seq=" << ntohl(tcpHeader->seq);
        if (tcpHeader->flags & 0x10) {
            info << " Ack=" << ntohl(tcpHeader->ack_seq);
        }
        info << " Len=" << payloadLength;
    } else {
        info << "Acknowledgment [ACK] ";
        info << "Seq=" << ntohl(tcpHeader->seq) << " Ack=" << ntohl(tcpHeader->ack_seq);
    }

    info << " Win=" << ntohs(tcpHeader->window);

    // Modified print statement to use the new protocol string
    std::cout << pid << "\t"
              << timestamp << "\t"
              << inet_ntoa(*(in_addr*)&ipHeader->saddr) << "\t"
              << inet_ntoa(*(in_addr*)&ipHeader->daddr) << "\t" 
              << protocolStr << "\t" << " " // Changed from "TCP" to protocolStr
              << header->len << "\t"
              << info.str() << "\t"
              << std::endl;


       PacketData packetData{
        srcPort,
       timestamp,  // implement this utility function
       inet_ntoa(*(in_addr*)&ipHeader->saddr),
        inet_ntoa(*(in_addr*)&ipHeader->daddr),
        protocolStr,
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