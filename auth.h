#pragma once
#ifndef AUTH_H
#define AUTH_H

#include <iostream>
#include <map>
#include <string>
#include <fstream>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>

#define KEY_LENGTH 32 // 32 Byte key => 256-bit key for symmetric encryption

// Function to check if the file exists
bool fileExists(const std::string& filename) {
    std::ifstream infile(filename);
    return infile.good();
}

bool generateAuthFile(const std::string& authFilename) {
    unsigned char key[KEY_LENGTH]; // Buffer for the symmetric key

    // Generate a random 256-bit symmetric key
    if (RAND_bytes(key, KEY_LENGTH) != 1) {
        std::cerr << "Error generating random key: " << ERR_reason_error_string(ERR_get_error()) << std::endl;
        return false;
    }

    // Write the key to the auth file (in hex format for human readability)
    std::ofstream authFile(authFilename, std::ios::out | std::ios::trunc);
    if (!authFile) {
        std::cerr << "Error opening file: " << authFilename << std::endl;
        return false;
    }

    authFile << "symmetric_key: ";
    for (int i = 0; i < KEY_LENGTH; ++i) {
        authFile << std::hex << (int)key[i];
    }
    authFile.close();

    std::cout << "Authentication file created with symmetric key." << std::endl;
    return true;
}


std::string read_auth_key(std::string& authFilename) {
    std::ifstream authFile(authFilename);
    if (!authFile.is_open()) {
        std::cerr << "Error opening authentication file: " << authFilename << std::endl;
        return "";
    }

    std::string line;
    std::string key;

    // Read the file line by line
    while (std::getline(authFile, line)) {
        // Check if the line contains "symmetric_key"
        std::size_t pos = line.find("symmetric_key: ");
        if (pos != std::string::npos) {
            // Extract the key part from the line (after "symmetric_key: ")
            key = line.substr(pos + std::string("symmetric_key: ").length());
            break;
        }
    }

    authFile.close();

    if (key.empty()) {
        std::cerr << "Error: No symmetric key found in the authentication file." << std::endl;
        return "";
    }

    return key;
}
#endif 
