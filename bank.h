#ifndef BANK_H
#define BANK_H

#include <cppconn/driver.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h> // Added for SSL support
#include <openssl/err.h> // Added for SSL error handling
#include <sstream>
#include <fstream>
#include <cstring>
#include <map>
#include <string>
#include <unistd.h>
#include <iostream>

// Hash the pin using a secure hashing algorithm (e.g., bcrypt)
std::string hashPin(const std::string& pin) {
    // Replace with actual bcrypt or other secure hash implementation
    return "hashed_" + pin;
}

// Authenticate the client by checking account_number and pin from the database
bool authenticateClient(const std::string& account_number, const std::string& pin, sql::Connection *conn) {
    sql::PreparedStatement *pstmt;
    sql::ResultSet *res;
    bool authenticated = false;

    // PIN should be hashed before being compared in the database (e.g., bcrypt)
    std::string hashed_pin = hashPin(pin); // Replace with actual hashing implementation

    pstmt = conn->prepareStatement("SELECT * FROM customers WHERE account_number = ? AND pin = ?");
    pstmt->setString(1, account_number);
    pstmt->setString(2, hashed_pin);
    res = pstmt->executeQuery();

    if (res->next()) {
        authenticated = true;
    }

    delete res;
    delete pstmt;
    return authenticated;
}



// Handle client requests
void handleClient(int clientSocket, SSL *ssl, sql::Connection *conn) {
    char buffer[1024];
    bzero(buffer, 1024);

    // Receive client data securely via SSL
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        std::cerr << "Error receiving data" << std::endl;
        return;
    }
    std::string account_number, pin;
    
    // Extract account_number and pin (assuming a simple format "account_number pin")
    std::istringstream iss(buffer);
    iss >> account_number >> pin;

    // Add input validation to prevent buffer overflow or SQL injection
    if (account_number.empty() || pin.empty() || account_number.length() > 20 || pin.length() > 10) {
        std::string response = "Invalid input format\n";
        SSL_write(ssl, response.c_str(), response.size());
        return;
    }

    if (authenticateClient(account_number, pin, conn)) {
        std::string response = "Authentication successful\n";
        SSL_write(ssl, response.c_str(), response.size());
    } else {
        std::string response = "Authentication failed\n";
        SSL_write(ssl, response.c_str(), response.size());
    }
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

// Initialize MySQL connection
sql::Connection* initDatabaseConnection(const std::map<std::string, std::string>& auth) {
    sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
    sql::Connection *conn = driver->connect(auth.at("host"), auth.at("user"), auth.at("password"));
    conn->setSchema(auth.at("database"));
    return conn;
}

// Initialize SSL context
SSL_CTX* initSSLContext() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 || 
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Listen for incoming client connections over SSL
void listenForConnections(int port, const std::map<std::string, std::string>& auth, SSL_CTX* ctx) {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addr_size = sizeof(clientAddr);

    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return;
    }

    // Configure server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port); // Port from -p option
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket to the port
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error binding to port" << std::endl;
        return;
    }

    // Listen for incoming connections
    if (listen(serverSocket, 10) == 0) {
        std::cout << "Bank is listening on port " << port << std::endl;
    } else {
        std::cerr << "Error listening on socket" << std::endl;
        return;
    }

    // Accept incoming client connections and handle each one
    while ((clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addr_size))) {
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientSocket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            std::cout << "Client connected via SSL." << std::endl;
            sql::Connection *conn = initDatabaseConnection(auth);
            handleClient(clientSocket, ssl, conn);
            delete conn;
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);
    }
}


#endif // BANK_H
