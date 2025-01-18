#ifndef TCP_INSPECTOR_H
#define TCP_INSPECTOR_H

#include "network_headers.h"

class TCPInspector {
public:
    bool inspect(const u_char *packet, const struct pcap_pkthdr *header);
};

#endif // TCP_INSPECTOR_H