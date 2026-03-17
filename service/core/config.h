#pragma once

#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>

namespace mpsi {

// Parse a simple key = value config file.
// Lines starting with '#' are comments. Blank lines are ignored.
// Returns key-value pairs with whitespace trimmed from both key and value.
inline std::unordered_map<std::string, std::string>
parseConfigFile(const std::string& path) {
    std::unordered_map<std::string, std::string> result;
    std::ifstream file(path);
    if (!file.is_open())
        throw std::runtime_error("Cannot open config file: " + path);

    std::string line;
    while (std::getline(file, line)) {
        // Strip leading/trailing whitespace
        auto start = line.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        line = line.substr(start);

        // Skip comments
        if (line[0] == '#') continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        // Trim whitespace
        auto trimEnd = key.find_last_not_of(" \t");
        if (trimEnd != std::string::npos) key = key.substr(0, trimEnd + 1);
        auto valStart = val.find_first_not_of(" \t");
        if (valStart != std::string::npos) val = val.substr(valStart);
        auto valEnd = val.find_last_not_of(" \t\r\n");
        if (valEnd != std::string::npos) val = val.substr(0, valEnd + 1);
        else val.clear();

        result[key] = val;
    }
    return result;
}

} // namespace mpsi
