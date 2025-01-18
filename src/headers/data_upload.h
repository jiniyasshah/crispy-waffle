#ifndef DATA_UPLOAD_H 
#define DATA_UPLOAD_H

#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>

void sendToServer(const std::string &packetData, bool isMalicious);
#pragma comment(lib, "winhttp.lib")

#endif // DATA_UPLOAD_H