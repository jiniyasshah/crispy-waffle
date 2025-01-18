#ifndef UDP_INSPECTOR_H
#define UDP_INSPECTOR_H

#include "network_headers.h"

class UDPInspector {
public:
    bool inspect(const u_char *packet, const struct pcap_pkthdr *header);
};

#endif // UDP_INSPECTOR_H