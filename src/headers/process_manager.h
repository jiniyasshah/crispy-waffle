#ifndef PROCESS_MANAGER_H
#define PROCESS_MANAGER_H

// Important: Include order matters!
#define WIN32_LEAN_AND_MEAN  // Prevent winsock.h inclusion
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

class ProcessManager {
public:
    static ProcessManager& getInstance();
    
    // Delete copy constructor and assignment operator
    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;

    // Initialize the manager - call this once at startup
    void initialize();
    
    // Get current process ID
    DWORD getCurrentProcessId() const { return currentProcessId; }
    
    // Get process ID for a specific connection
    DWORD getProcessIdForConnection(const char* srcIp, UINT16 srcPort,
                                  const char* dstIp, UINT16 dstPort);

private:
    ProcessManager() : currentProcessId(0) {}
    DWORD currentProcessId;
};

#endif // PROCESS_MANAGER_H