#include "bank.h"
#include <iostream>
#include <map>
#include <string>

int main(int argc, char *argv[]) {
    int opt;
    std::string authFile;
    int port = 0;

    // Parse command-line options using getopt
    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
            case 'p':
                port = std::stoi(optarg); // Get the port from the -p flag
                break;
            case 's':
                authFile = optarg; // Get the auth file from the -s flag
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " -p <port> -s <auth_file>" << std::endl;
                return EXIT_FAILURE;
        }
    }

    if (port == 0 || authFile.empty()) {
        std::cerr << "Port or auth file not provided. Use -p <port> and -s <auth_file>." << std::endl;
        return EXIT_FAILURE;
    }

    std::map<std::string, std::string> auth = loadAuthDetails(authFile);
    
    // Check if all necessary fields (host, user, password, database) are present in the auth file
    if (auth.find("host") == auth.end() || auth.find("user") == auth.end() || 
        auth.find("password") == auth.end() || auth.find("database") == auth.end()) {
        std::cerr << "Missing required authentication details in the auth file." << std::endl;
        return EXIT_FAILURE;
    }

    // Initialize SSL context
    SSL_CTX *ctx = initSSLContext();

    // Listen for connections securely using SSL
    listenForConnections(port, auth, ctx);

    SSL_CTX_free(ctx);
    return 0;
}
