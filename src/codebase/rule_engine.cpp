// src/rule_engine.cpp
#include "./headers/rule_engine.h"
#include <fstream>
#include <sstream>
#include <iostream>

bool RuleEngine::loadRules(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open rule file: " << filePath << std::endl;
        return false;
    }

    std::string line;
    int lineNumber = 0;
    rules.clear();

    while (std::getline(file, line)) {
        lineNumber++;
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }

        try {
            Rule rule = parseRule(line);
            if (validateRule(rule)) {
                rules.push_back(rule);
                
            } else {
                std::cerr << "Warning: Invalid rule at line " << lineNumber << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error parsing rule at line " << lineNumber << ": " << e.what() << std::endl;
            continue;
        }
    }

    return !rules.empty();
}

Rule RuleEngine::parseRule(const std::string& ruleString) {
    Rule rule;
    
    size_t optionsStart = ruleString.find('(');
    if (optionsStart == std::string::npos) {
        throw std::runtime_error("Invalid rule format: missing options section");
    }

    std::string header = ruleString.substr(0, optionsStart);
    std::string options = ruleString.substr(optionsStart + 1);
    
    if (!options.empty() && options.back() == ')') {
        options.pop_back();
    }

    parseHeader(header, rule);
    parseOptions(options, rule);

    // Only create regex pattern if content is specified
    if (rule.options.find("content") != rule.options.end()) {
        std::string content = rule.options["content"];
        
        // Remove quotes if present
        if (content.size() >= 2 && content.front() == '"' && content.back() == '"') {
            content = content.substr(1, content.size() - 2);
        }
        
        // Escape special regex characters
        std::string escapedContent;
        for (char c : content) {
            if (strchr("[](){}.*+?^$\\|", c) != nullptr) {
                escapedContent += '\\';
            }
            escapedContent += c;
        }
        
        rule.pattern = escapedContent;
        
        // Create the regex pattern with proper flags
        try {
            if (rule.nocase) {
                rule.regexPattern = std::regex(rule.pattern, 
                    std::regex::optimize | std::regex::icase);
            } else {
                rule.regexPattern = std::regex(rule.pattern, 
                    std::regex::optimize);
            }
        } catch (const std::regex_error& e) {
            throw std::runtime_error("Invalid regex pattern: " + content);
        }
    }

    return rule;
}

void RuleEngine::parseOptions(const std::string& options, Rule& rule) {
    std::vector<std::string> optionsList;
    std::string current;
    bool inQuotes = false;
    
    for (char c : options) {
        if (c == '"') {
            inQuotes = !inQuotes;
            current += c;
        } else if (c == ';' && !inQuotes) {
            if (!current.empty()) {
                optionsList.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }
    if (!current.empty()) {
        optionsList.push_back(current);
    }

    for (const auto& opt : optionsList) {
        auto [key, value] = parseOption(opt);
        if (key == "nocase") {
            rule.nocase = true;
        } else if (!key.empty()) {
            rule.options[key] = value;
        }
    }
}

std::string RuleEngine::match(const std::string& packetData) {
    for (const auto& rule : rules) {
        try {
            // Only try to match if the rule has a pattern
            if (!rule.pattern.empty() && 
                std::regex_search(packetData, rule.regexPattern)) {
                // Return the msg from options if it exists
                auto it = rule.options.find("msg");
                if (it != rule.options.end()) {
                    return it->second;
                }
            }
        } catch (const std::regex_error& e) {
            std::cerr << "Regex error with pattern '" << rule.pattern 
                     << "': " << e.what() << std::endl;
            continue;
        }
    }
    return ""; // Return empty string if no match found
}

void RuleEngine::parseHeader(const std::string& header, Rule& rule) {
    std::istringstream iss(header);
    std::vector<std::string> parts;
    std::string part;
    
    while (iss >> part) {
        parts.push_back(part);
    }

    if (parts.size() < 7) {
        throw std::runtime_error("Invalid rule header: insufficient components");
    }

    rule.action = parts[0];
    rule.protocol = parts[1];
    rule.sourceIP = parts[2];
    rule.sourcePort = parts[3];
    rule.direction = parts[4];
    rule.destIP = parts[5];
    rule.destPort = parts[6];
}

std::pair<std::string, std::string> RuleEngine::parseOption(const std::string& option) {
    std::string trimmed = option;
    // Trim whitespace
    trimmed.erase(0, trimmed.find_first_not_of(" \t"));
    trimmed.erase(trimmed.find_last_not_of(" \t") + 1);

    size_t colonPos = trimmed.find(':');
    if (colonPos == std::string::npos) {
        return {trimmed, ""}; // Option without value
    }

    std::string key = trimmed.substr(0, colonPos);
    std::string value = trimmed.substr(colonPos + 1);
    
    // Remove quotes if present
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
    }

    return {key, value};
}

bool RuleEngine::validateRule(const Rule& rule) const {
    // Validate action
    std::vector<std::string> validActions = {"alert", "pass", "drop", "reject"};
    if (std::find(validActions.begin(), validActions.end(), rule.action) == validActions.end()) {
        return false;
    }

    // Validate protocol
    std::vector<std::string> validProtocols = {"tcp", "udp", "icmp", "ip", "http"};
    if (std::find(validProtocols.begin(), validProtocols.end(), rule.protocol) == validProtocols.end()) {
        return false;
    }

    // Validate direction
    if (rule.direction != "->" && rule.direction != "<>") {
        return false;
    }

    return true;
}