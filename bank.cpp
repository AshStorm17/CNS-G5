#include "validation.h"
#include "bank.h"
#include "auth.h"
#include <iostream>
#include <map>
#include <string>
#include <cstdio>
#include <csignal>
#include <fstream>

std::string authFilename;

// Signal handler for SIGINT (Ctrl + C)
void signalHandler(int signum) {
    // Cleanup resources before exiting
    std::cout << "\nInterrupt signal (" << signum << ") received. Closing the bank..." << std::endl;

    // Delete the auth file
    if (remove(authFilename.c_str()) != 0) {
        std::cerr << "Error deleting the authentication file: " << authFilename << std::endl;
    } else {
        std::cout << "Authentication file deleted successfully." << std::endl;
    }

    // Exit the program
    exit(signum);
}

int main(int argc, char *argv[]) {
    int opt;
    std::string auth_key;
    int port = 0;

    signal(SIGINT, signalHandler);

    // Parse command-line options using getopt
    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
            case 'p':
                port = std::stoi(optarg); // Get the port from the -p flag
                break;
            case 's':
                authFilename = optarg; // Get the auth file from the -s flag
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " -p <port> -s <auth_file>" << std::endl;
                return EXIT_FAILURE;
        }
    }

    if (!isValidPort(port)) {
        std::cerr << "Port number must be between 1024 and 65535 inclusively." << std::endl;
        return EXIT_FAILURE;
    }

    // Check if authentication file exists, if not, create it
    if (!fileExists(authFilename)) {
        if (!generateAuthFile(authFilename)) {
            std::cerr << "Failed to generate authentication file." << std::endl;
            return EXIT_FAILURE;
        }
        auth_key = read_auth_key(authFilename);
    }
    else{
        std::cerr << "Authentication file already exists." << std::endl;
        return EXIT_FAILURE;
    }

    std::map<std::string, std::string> config = readConfig("db_config.txt");
    
    // Check if all necessary fields (host, user, password, database) are present in the auth file
    if (config.find("host") == config.end() || config.find("user") == config.end() || 
        config.find("password") == config.end() || config.find("database") == config.end()) {
        std::cerr << "Missing required authentication details in the auth file." << std::endl;
        return EXIT_FAILURE;
    }

    // Initialize SSL context
    SSL_CTX *ctx = initSSLContext();

    // Listen for connections securely using SSL
    listenForConnections(port, config, ctx, auth_key);

    SSL_CTX_free(ctx);

    if (remove(authFilename.c_str()) != 0) {
        std::cerr << "Error deleting the authentication file: " << authFilename << std::endl;
    } else {
        std::cout << "Authentication file deleted successfully." << std::endl;
    }
    
    return 0;
}
