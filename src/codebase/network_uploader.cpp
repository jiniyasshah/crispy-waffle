#include "../headers/network_uploader.h"
#include <sstream>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

NetworkUploader& NetworkUploader::getInstance() {
    static NetworkUploader instance;
    return instance;
}

NetworkUploader::NetworkUploader() 
    : hSession(NULL), hConnect(NULL), hRequest(NULL), serverPort(80) {}

bool NetworkUploader::initialize(const std::wstring& userAgent) {
    cleanup();  // Ensure clean state
    
    hSession = WinHttpOpen(userAgent.c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    
    return (hSession != NULL);
}

void NetworkUploader::setServerDetails(const std::wstring& host, 
                                     uint16_t port, 
                                     const std::wstring& path) {
    serverHost = host;
    serverPort = port;
    serverPath = path;
}

bool NetworkUploader::uploadPacketData(const std::string& jsonData) {
    if (!hSession || serverHost.empty()) {
        return false;
    }

    // Create new connection for each upload
    hConnect = WinHttpConnect(hSession, serverHost.c_str(), serverPort, 0);
    if (!hConnect) return false;

    bool result = sendRequest(jsonData);
    
    // Cleanup connection
    if (hConnect) {
        WinHttpCloseHandle(hConnect);
        hConnect = NULL;
    }
    if (hRequest) {
        WinHttpCloseHandle(hRequest);
        hRequest = NULL;
    }

    return result;
}

bool NetworkUploader::sendRequest(const std::string& jsonData) {
    hRequest = WinHttpOpenRequest(hConnect,
        L"POST",
        serverPath.c_str(),
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);

    if (!hRequest) return false;

    // Set headers
    LPCWSTR headers = L"Content-Type: application/json\r\n";
    WinHttpAddRequestHeaders(hRequest, headers, -1L, WINHTTP_ADDREQ_FLAG_ADD);

    // Send request
    BOOL result = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        (LPVOID)jsonData.c_str(),
        jsonData.length(),
        jsonData.length(),
        0);

    if (result) {
        result = WinHttpReceiveResponse(hRequest, NULL);
        if (result) {
            std::string response = readResponse();
            // Log response if needed
        }
    }

    return result;
}

std::string NetworkUploader::readResponse() {
    std::string response;
    DWORD bytesAvailable = 0;
    DWORD bytesRead = 0;

    do {
        bytesAvailable = 0;
        WinHttpQueryDataAvailable(hRequest, &bytesAvailable);
        
        if (bytesAvailable == 0) break;

        std::vector<char> buffer(bytesAvailable + 1);
        WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead);
        response.append(buffer.data(), bytesRead);
    } while (bytesAvailable > 0);

    return response;
}

void NetworkUploader::cleanup() {
    if (hRequest) {
        WinHttpCloseHandle(hRequest);
        hRequest = NULL;
    }
    if (hConnect) {
        WinHttpCloseHandle(hConnect);
        hConnect = NULL;
    }
    if (hSession) {
        WinHttpCloseHandle(hSession);
        hSession = NULL;
    }
}

NetworkUploader::~NetworkUploader() {
    cleanup();
}

std::string PacketData::toJson() const {
    std::ostringstream json;
    json << "{\"source_port\":" << source_port
         << ",\"timestamp\":\"" << timestamp
         << "\",\"source_ip\":\"" << source_ip
         << "\",\"destination_ip\":\"" << destination_ip
         << "\",\"protocol\":\"" << protocol
         << "\",\"length\":" << length
         << ",\"request_line\":\"" << request_line
         << "\",\"status\":\"" << status
         << "\",\"alert_type\":\"" << alert_type
         << "\",\"severity\":\"" << severity
         << "\",\"signature_id\":\"" << signature_id
         << "\"}";
    return json.str();
}