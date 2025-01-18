#ifndef DNS_INSPECTOR_H
#define DNS_INSPECTOR_H

#include "network_headers.h"

class DNSInspector {
public:
    bool inspect(const u_char *packet, const struct pcap_pkthdr *header);
};

#endif // DNS_INSPECTOR_H

