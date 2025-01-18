#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <string>
#include <vector>
#include <regex>
#include <map>

struct Rule {
    // Header components
    std::string action;        // alert, pass, drop, reject
    std::string protocol;      // tcp, udp, icmp, ip
    std::string sourceIP;
    std::string sourcePort;
    std::string direction;     // -> or <>
    std::string destIP;
    std::string destPort;
    
    // Options
    std::map<std::string, std::string> options;
    bool nocase;              // Flag for case-insensitive matching
    
    // Pattern for matching
    std::string pattern;
    std::regex regexPattern;

    Rule(const std::string& p) 
        : pattern(p), regexPattern(p), nocase(false) {}
    
    Rule() : nocase(false) {}  // Initialize nocase to false by default
    
    // Helper method to set pattern with proper flags
    void setPattern(const std::string& p) {
        pattern = p;
        try {
            if (nocase) {
                regexPattern = std::regex(pattern, std::regex::optimize | std::regex::icase);
            } else {
                regexPattern = std::regex(pattern, std::regex::optimize);
            }
        } catch (const std::regex_error& e) {
            throw std::runtime_error("Invalid regex pattern: " + pattern);
        }
    }
};

class RuleEngine {
public:
    bool loadRules(const std::string& filePath);
    std::string match(const std::string& packetData);
    
    // Added debug methods
    void printRules() const; // For debugging rules
    size_t getRuleCount() const { return rules.size(); }

private:
    std::vector<Rule> rules;
    
    // Helper functions for rule parsing
    Rule parseRule(const std::string& ruleString);
    void parseHeader(const std::string& header, Rule& rule);
    void parseOptions(const std::string& options, Rule& rule);
    std::pair<std::string, std::string> parseOption(const std::string& option);
    bool validateRule(const Rule& rule) const;
    
};

#endif