#ifndef NETWORK_HEADERS_H
#define NETWORK_HEADERS_H

#include <pcap.h>
#include <winsock2.h> // For basic socket functions
#include <ws2tcpip.h> // For inet_ntoa
#include <windows.h>  // For Win32 API

// Constants for Ethernet frames
#define ETHERNET_HEADER_SIZE 14
#define ETHERTYPE_IP 0x0800

// IPv4 header
struct IPHeader {
    unsigned char  ihl:4;         // IP header length
    unsigned char  version:4;     // IP version
    unsigned char  tos;           // Type of service
    unsigned short tot_len;       // Total length
    unsigned short id;            // Identification
    unsigned short frag_off;      // Fragment offset
    unsigned char  ttl;           // Time to live
    unsigned char  protocol;      // Protocol
    unsigned short check;         // Header checksum
    unsigned int   saddr;         // Source address
    unsigned int   daddr;         // Destination address
};

// TCP header
struct TCPHeader {
    unsigned short source;        // Source port
    unsigned short dest;          // Destination port
    unsigned int   seq;           // Sequence number
    unsigned int   ack_seq;       // Acknowledgement number
    unsigned char  res1:4;        // Reserved
    unsigned char  doff:4;        // Data offset
    unsigned char  flags;         // Flags
    unsigned short window;        // Window size
    unsigned short check;         // Checksum
    unsigned short urg_ptr;       // Urgent pointer
};

// UDP header
struct UDPHeader {
    unsigned short source;        // Source port
    unsigned short dest;          // Destination port
    unsigned short len;           // Datagram length
    unsigned short check;         // Checksum
};

// DNS header
// In network_headers.h
#pragma pack(push, 1)
struct DNSHeader {
    uint16_t id;      // Identification number
    uint16_t flags;   // DNS Flags
    uint16_t qdcount; // Number of questions
    uint16_t ancount; // Number of answers
    uint16_t nscount; // Number of authority records
    uint16_t arcount; // Number of additional records
};
#pragma pack(pop)

#endif // NETWORK_HEADERS_H