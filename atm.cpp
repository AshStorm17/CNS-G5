#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <jsoncpp/json/json.h> // Make sure you have the JSON library available
#include <cppconn/driver.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX* initClientSSLContext() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    const SSL_METHOD* method = TLS_client_method();  // Use TLS method for client
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to load authentication details from a file
std::map<std::string, std::string> loadAuthDetails(const std::string &filename) {
    std::ifstream file(filename);
    std::map<std::string, std::string> auth;
    std::string key, value;

    while (file >> key >> value) {
        auth[key] = value;
    }

    return auth;
}

bool sendSSLRequest(SSL* ssl, const std::string& request, std::string& response) {
    if (SSL_write(ssl, request.c_str(), request.size()) <= 0) {
        std::cerr << "Error sending request to the bank server." << std::endl;
        return false;
    }

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    int bytesReceived = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytesReceived <= 0) {
        std::cerr << "Error receiving response from the bank server." << std::endl;
        return false;
    }

    response = std::string(buffer, bytesReceived);
    return true;
}


// Function to send a request to the bank server and receive a response
bool sendRequest(int sockfd, const std::string &request, std::string &response) {
    if (send(sockfd, request.c_str(), request.size(), 0) < 0) {
        std::cerr << "Error sending request to the bank server." << std::endl;
        return false;
    }
    
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    
    int bytesReceived = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived < 0) {
        std::cerr << "Error receiving response from the bank server." << std::endl;
        return false;
    }

    response = std::string(buffer, bytesReceived);
    return true;
}

// Function to generate a random 4-digit PIN code
int generateRandomPin() {
    return rand() % 9000 + 1000; // Generates a 4-digit PIN code
}

// Main function for the ATM application
int main(int argc, char *argv[]) {
    std::string authFile = "bank.auth";
    std::string ipAddress = "127.0.0.1";
    int port = 3000;
    std::string cardFile;
    std::string account;
    std::string mode;
    std::string balance;

    int opt;
    while ((opt = getopt(argc, argv, "s:i:p:c:a:n:d:w:g:")) != -1) {
        switch (opt) {
            case 's':
                authFile = optarg;
                break;
            case 'i':
                ipAddress = optarg;
                break;
            case 'p':
                port = std::stoi(optarg);
                break;
            case 'c':
                cardFile = optarg;
                break;
            case 'a':
                account = optarg;
                break;
            case 'n':
                mode = "CREATE";
                balance = optarg;
                break;
            case 'd':
                mode = "DEPOSIT";
                balance = optarg;
                break;
            case 'w':
                mode = "WITHDRAW";
                balance = optarg;
                break;
            case 'g':
                mode = "GET_BALANCE";
                break;
            default:
                std::cerr << "Invalid command line option." << std::endl;
                return 255;
        }
    }

    // Validate required parameters
    if (account.empty() || (mode.empty() && !balance.empty()) || (mode != "GET_BALANCE" && balance.empty())) {
        std::cerr << "Account and operation parameters are required." << std::endl;
        return 255;
    }

    // Load authentication details
    std::map<std::string, std::string> auth = loadAuthDetails(authFile);
    if (auth.empty()) {
        std::cerr << "Failed to load authentication details." << std::endl;
        return 255;
    }

    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error creating socket." << std::endl;
        return 255;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    if (inet_pton(AF_INET, ipAddress.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid IP address." << std::endl;
        close(sockfd);
        return 255;
    }

    // Connect to the bank server
    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error connecting to the bank server." << std::endl;
        close(sockfd);
        return 255;
    }


    // Initialize SSL
    SSL_CTX* ctx = initClientSSLContext();
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        std::cerr << "Error during SSL handshake." << std::endl;
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 255;
    }

    std::cout << "Connected with " << SSL_get_cipher(ssl) << " encryption" << std::endl;


    // Determine the operation based on mode
    std::string response;
    if (mode == "CREATE") {
        // Check if card file exists
        std::ifstream cardFileCheck(cardFile);
        if (cardFileCheck.good()) {
            std::cerr << "Card file already exists. Account creation failed." << std::endl;
            close(sockfd);
            return 255;
        }

        // Create JSON request for creating an account
        Json::Value jsonRequest;
        jsonRequest["operation"] = "CREATE";
        jsonRequest["account"] = account;
        jsonRequest["initial_balance"] = std::stod(balance);
        std::string requestStr = jsonRequest.toStyledString();

        // Send request to bank
        if (sendSSLRequest(ssl, requestStr, response)) {
            std::cout << response << std::endl;
        }

        // Create the card file with a random PIN code
        std::ofstream newCardFile(cardFile);
        if (newCardFile) {
            int pin_code = generateRandomPin();
            newCardFile << pin_code;
            newCardFile.close();
            std::cout << "Card file created with PIN: " << pin_code << std::endl;
        } else {
            std::cerr << "Error creating card file." << std::endl;
        }

    } else if (mode == "DEPOSIT" || mode == "WITHDRAW") {
        // Create JSON request for depositing or withdrawing money
        Json::Value jsonRequest;
        jsonRequest["operation"] = mode;
        jsonRequest["account"] = account;
        jsonRequest["amount"] = std::stod(balance);
        std::string requestStr = jsonRequest.toStyledString();

        // Send request to bank
        if (sendSSLRequest(ssl, requestStr, response)) {
            std::cout << response << std::endl;
        }

    } else if (mode == "GET_BALANCE") {
        // Create JSON request for getting balance
        Json::Value jsonRequest;
        jsonRequest["operation"] = "GET_BALANCE";
        jsonRequest["account"] = account;
        std::string requestStr = jsonRequest.toStyledString();

        // Send request to bank
        if (sendSSLRequest(ssl, requestStr, response)) {
            std::cout << response << std::endl;
        }
    }

    // Cleanup
    close(sockfd);
    return 0;
}
