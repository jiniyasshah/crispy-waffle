#include <iostream>
#include <string>
#include "./headers/rule_engine.h"
#include "./headers/packet_inspector.h"
#include <windows.h> 
int main() {
    //For Colored ANSI outputs
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    std::cout << "\033[1;36m" << "NIDS Starting..." << "\033[0m" << std::endl; 
    std::string ruleFilePath = "rules/sample.rules";
    std::cout << "Loading rules from: " << ruleFilePath << std::endl;
    
    //Load the rules
    RuleEngine ruleEngine;
    if (!ruleEngine.loadRules(ruleFilePath)) {
        std::cout << "\033[1;31m" << "Failed to load rules!" << "\033[0m" << std::endl;
        return 1;
    }

    std::cout << "\033[1;32m" << "Rules loaded successfully." << "\033[0m" << std::endl;

    PacketInspector packetInspector(ruleEngine);
    packetInspector.startInspection();

    return 0;
}

