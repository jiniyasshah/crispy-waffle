#ifndef PACKET_INSPECTOR_H
#define PACKET_INSPECTOR_H

#include "http_inspector.h"
#include "dns_inspector.h"
#include "tcp_inspector.h"
#include "udp_inspector.h"
#include "rule_engine.h"

class PacketInspector {
public:
    PacketInspector(RuleEngine &engine);
    void startInspection();
private:
    RuleEngine &ruleEngine;
    HTTPInspector httpInspector;
    DNSInspector dnsInspector;
    TCPInspector tcpInspector;
    UDPInspector udpInspector;
    
    // Declare packetHandler as a static member function
    static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    
    void processPacket(const u_char *packet, const struct pcap_pkthdr *header);
};

#endif // PACKET_INSPECTOR_H