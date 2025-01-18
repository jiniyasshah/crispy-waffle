#include "../headers/data_upload.h"

void sendToServer(const std::string &packetData, bool isMalicious) {
    // Initialize WinHTTP session
    HINTERNET hSession = WinHttpOpen(L"Packet Inspector/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cerr << "Failed to open WinHTTP session." << std::endl;
        return;
    }

    // Connect to the server
    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 3000, 0);
    if (!hConnect) {
        std::cerr << "Failed to connect to server." << std::endl;
        WinHttpCloseHandle(hSession);
        return;
    }

    // Open a POST request
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/packet", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        std::cerr << "Failed to open HTTP request." << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // Prepare the JSON payload
    std::string jsonPayload = "{ \"data\": \"" + packetData + "\", \"malicious\": " + (isMalicious ? "true" : "false") + " }";

    // Send the request
    BOOL result = WinHttpSendRequest(hRequest, L"Content-Type: application/json\r\n", -1L, (LPVOID)jsonPayload.c_str(), (DWORD)jsonPayload.size(), (DWORD)jsonPayload.size(), 0);

    if (!result) {
        std::cerr << "Failed to send HTTP requests." << std::endl;
    } else {
        // Wait for a response
        BOOL response = WinHttpReceiveResponse(hRequest, NULL);
        if (!response) {
            std::cerr << "Failed to receive response from server." << std::endl;
        } else {
           
        }
    }

    // Clean up
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}