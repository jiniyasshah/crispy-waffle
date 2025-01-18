// src/headers/http_inspector.h
#ifndef HTTP_INSPECTOR_H
#define HTTP_INSPECTOR_H

#include <string>
#include "network_headers.h"
#include "rule_engine.h"
#include <pcap.h>

class HTTPInspector {
public:
    HTTPInspector();
    bool inspect(const u_char *packet, const struct pcap_pkthdr *header);

private:
    RuleEngine ruleEngine;
    bool initialized;
    
    void initializeRules();
    bool isMalicious(const std::string& data);
};

#endif