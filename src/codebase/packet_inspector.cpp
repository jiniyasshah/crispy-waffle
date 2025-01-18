#include "../headers/packet_inspector.h"
#include "../headers/network_headers.h"
#include <iostream>
#include <pcap.h>

PacketInspector::PacketInspector(RuleEngine &engine)
    : ruleEngine(engine) {}

void PacketInspector::startInspection() {
    std::cout << "Starting real-time packet inspection..." << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDevs;
    pcap_if_t *device;

    // Get the list of available devices
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }
    
    std::cout << "\n" << "ID"<<"\t"<<"Available Devices" << std::endl;
    std::cout << "-----------------------------------------------------------------------------------------------------------" << std::endl;
    int i = 0;
    std::vector<pcap_if_t*> devices;
    
    // List all available devices and store them in a vector
    for (device = allDevs; device != nullptr; device = device->next) {
        std::cout  << "[" << ++i << "]" << "\t" << (device->description ? device->description : "No description available") << std::endl;
        devices.push_back(device);
    }

    // If no devices found, exit
    if (devices.empty()) {
        std::cerr << "No devices found!" << std::endl;
        pcap_freealldevs(allDevs);
        return;
    }

    // Prompt the user to choose a device
    int choice;
    std::cout << "\n" << "Enter the device ID you want to use: ";
    std::cin >> choice;

    // Check if the choice is valid
    if (choice < 1 || choice > static_cast<int>(devices.size())) {
        std::cerr << "Invalid device choice!" << std::endl;
        pcap_freealldevs(allDevs);
        return;
    }

    // Select the chosen device
    device = devices[choice - 1];
   std::cout << "Using device: " << "\033[38;5;130m"  // Brown/Orange color
          << (device->description ? device->description : "No description available") 
          << "\033[0m"  // Reset color
          << std::endl;

    // Open the selected device for packet capture (promiscuous mode = 1, timeout = 1000ms)
    pcap_t *handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        pcap_freealldevs(allDevs);
        return;
    }

    // Free the list of devices
    pcap_freealldevs(allDevs);
     std::cout << "-----------------------------------------------------------------------------------------------------------" << std::endl;
     std::cout << "ID" << "\t"
          << "Timestamp" << "\t" << "\t"
          << "Source IP" << "\t"
          << "Destination IP" << "\t" 
          << "Protocol"<< " "
          << "Length" << "\t"
          << "Info" << "\t"
          << std::endl;
    std::cout << "-----------------------------------------------------------------------------------------------------------" << std::endl;
    // Start capturing packets
    pcap_loop(handle, 0, PacketInspector::packetHandler, reinterpret_cast<u_char*>(this));

    // Close the capture handle
    pcap_close(handle);
}

// Define packetHandler function
void PacketInspector::packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PacketInspector *inspector = reinterpret_cast<PacketInspector*>(userData);
    inspector->processPacket(packet, pkthdr);
}

void PacketInspector::processPacket(const u_char *packet, const struct pcap_pkthdr *header) {
    const IPHeader *ipHeader = reinterpret_cast<const IPHeader*>(packet + ETHERNET_HEADER_SIZE);
    unsigned char protocol = ipHeader->protocol;
    
    switch (protocol) {
        case IPPROTO_TCP:
            if (httpInspector.inspect(packet, header)) {
                break; // If it's an HTTP packet, do not inspect further as TCP
            }
            tcpInspector.inspect(packet, header);
            break;
        case IPPROTO_UDP:
            if (dnsInspector.inspect(packet, header)) {
                break; // If it's a DNS packet, do not inspect further as UDP
            }
            udpInspector.inspect(packet, header);
            break;
        case IPPROTO_ICMP:
            // Handle ICMP packets if needed
            break;
        default:
            // std::cout << "Other protocol: " << (int)protocol << std::endl;
            break;
    }
}