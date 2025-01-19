#pragma once

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <memory>
#include <vector>
#include "utils.h"  // For any common utilities

class NetworkUploader {
public:
    // Singleton instance getter
    static NetworkUploader& getInstance();

    // Initialize the uploader
    bool initialize(const std::wstring& userAgent = L"NIDS-PacketUploader/1.0");
    
    // Configuration
    void setServerDetails(const std::wstring& host, uint16_t port, const std::wstring& path);

    // Upload packet data
    bool uploadPacketData(const std::string& jsonData);

    // Cleanup resources
    void cleanup();

    // Destructor
    ~NetworkUploader();

private:
    // Private constructor for singleton
    NetworkUploader();
    
    // Prevent copying
    NetworkUploader(const NetworkUploader&) = delete;
    NetworkUploader& operator=(const NetworkUploader&) = delete;

    // Internal helper methods
    bool sendRequest(const std::string& jsonData);
    std::string readResponse();

    // WinHTTP handles
    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;

    // Server configuration
    std::wstring serverHost;
    uint16_t serverPort;
    std::wstring serverPath;
};

// Packet data structure
struct PacketData {
    uint16_t source_port;
    std::string timestamp;
    std::string source_ip;
    std::string destination_ip;
    std::string protocol;
    uint32_t length;
    std::string request_line;
    std::string status;
    
    // Additional fields specific to your NIDS
    std::string alert_type;
    std::string severity;
    std::string signature_id;
    
    // Convert to JSON string
    std::string toJson() const;
};