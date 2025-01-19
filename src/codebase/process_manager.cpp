#define WIN32_LEAN_AND_MEAN
#include "../headers/process_manager.h"
#include <iostream>

ProcessManager& ProcessManager::getInstance() {
    static ProcessManager instance;
    return instance;
}

void ProcessManager::initialize() {
    currentProcessId = GetCurrentProcessId();
    std::cout << "Initialized ProcessManager with current PID: " << currentProcessId << std::endl;
}

DWORD ProcessManager::getProcessIdForConnection(const char* srcIp, UINT16 srcPort,
                                             const char* dstIp, UINT16 dstPort) {
    PMIB_TCPTABLE2 pTcpTable = nullptr;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    DWORD pid = 0;

    // Get the size needed for the table
    if (GetTcpTable2(nullptr, &dwSize, TRUE) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE2)malloc(dwSize);
        if (pTcpTable == nullptr) {
            return 0;
        }
    }

    // Get the actual table
    if ((dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            char localAddr[INET_ADDRSTRLEN];
            char remoteAddr[INET_ADDRSTRLEN];
            
            // Convert IP addresses to strings
            struct in_addr localIP, remoteIP;
            localIP.s_addr = pTcpTable->table[i].dwLocalAddr;
            remoteIP.s_addr = pTcpTable->table[i].dwRemoteAddr;
            
            inet_ntop(AF_INET, &localIP, localAddr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &remoteIP, remoteAddr, INET_ADDRSTRLEN);

            // Get ports (in host byte order)
            UINT16 localPort = ntohs((UINT16)pTcpTable->table[i].dwLocalPort);
            UINT16 remotePort = ntohs((UINT16)pTcpTable->table[i].dwRemotePort);

            // Check if this connection matches our packet
            if ((strcmp(localAddr, srcIp) == 0 && localPort == srcPort &&
                 strcmp(remoteAddr, dstIp) == 0 && remotePort == dstPort) ||
                (strcmp(localAddr, dstIp) == 0 && localPort == dstPort &&
                 strcmp(remoteAddr, srcIp) == 0 && remotePort == srcPort)) {
                pid = pTcpTable->table[i].dwOwningPid;
                break;
            }
        }
    }

    if (pTcpTable) {
        free(pTcpTable);
    }
    
    return pid;
}