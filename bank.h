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
#include <openssl/sha.h>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sstream>
#include <fstream>
#include <cstring>
#include <map>
#include <string>
#include <unistd.h>
#include <iostream>

// Hash the pin using a secure hashing algorithm
std::string hashPin(const std::string& pin) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, pin.c_str(), pin.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
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

// Function to create a new account
bool createAccount(const std::string& account_number, const std::string& pin, sql::Connection *conn) {
    sql::PreparedStatement *pstmt;
    bool success = false;

    // Hash the pin securely
    std::string hashed_pin = hashPin(pin);

    // Prepare and execute SQL statement
    pstmt = conn->prepareStatement("INSERT INTO customers (account_number, pin) VALUES (?, ?)");
    pstmt->setString(1, account_number);
    pstmt->setString(2, hashed_pin);

    try {
        pstmt->executeUpdate();
        success = true;
    } catch (sql::SQLException &e) {
        std::cerr << "Error creating account: " << e.what() << std::endl;
    }

    delete pstmt;
    return success;
}

// Function to delete an account
bool deleteAccount(const std::string& account_number, const std::string& pin, sql::Connection *conn) {
    sql::PreparedStatement *pstmt;
    bool success = false;

    std::string hashed_pin = hashPin(pin);

    pstmt = conn->prepareStatement("DELETE FROM customers WHERE account_number = ? AND pin = ?");
    pstmt->setString(1, account_number);
    pstmt->setString(2, hashed_pin);

    try {
        int rowsAffected = pstmt->executeUpdate();
        success = (rowsAffected > 0);
    } catch (sql::SQLException &e) {
        std::cerr << "Error deleting account: " << e.what() << std::endl;
    }

    delete pstmt;
    return success;
}

// Function to view account details
void viewAccountDetails(const std::string& account_number, sql::Connection *conn, SSL *ssl) {
    sql::PreparedStatement *pstmt;
    sql::ResultSet *res;

    pstmt = conn->prepareStatement("SELECT * FROM customers WHERE account_number = ?");
    pstmt->setString(1, account_number);
    res = pstmt->executeQuery();

    if (res->next()) {
        std::string response = "Account Number: " + res->getString("account_number") + 
                               "\nBalance: " + res->getString("balance") + "\n";
        SSL_write(ssl, response.c_str(), response.size());
    } else {
        std::string response = "Account not found\n";
        SSL_write(ssl, response.c_str(), response.size());
    }

    delete res;
    delete pstmt;
}

// Function to modify account details (e.g., update balance) with PIN authentication
bool modifyAccountDetails(const std::string& account_number, const std::string& pin, const std::string& new_balance, sql::Connection *conn) {
    sql::PreparedStatement *pstmt;
    sql::ResultSet *res;
    bool authenticated = false;

    std::string hashed_pin = hashPin(pin);

    // First, authenticate the user
    pstmt = conn->prepareStatement("SELECT * FROM customers WHERE account_number = ? AND pin = ?");
    pstmt->setString(1, account_number);
    pstmt->setString(2, hashed_pin);
    res = pstmt->executeQuery();

    if (res->next()) {
        authenticated = true;
    }

    delete res;
    delete pstmt;

    // If authenticated, proceed to modify the balance
    if (authenticated) {
        pstmt = conn->prepareStatement("UPDATE customers SET balance = ? WHERE account_number = ?");
        pstmt->setString(1, new_balance);
        pstmt->setString(2, account_number);

        try {
            pstmt->executeUpdate();
            delete pstmt; // Clean up after execution
            return true; // Modification successful
        } catch (sql::SQLException &e) {
            std::cerr << "Error modifying account details: " << e.what() << std::endl;
        }
    }

    delete pstmt; // Clean up if not authenticated or if error occurred
    return false; // Modification failed or not authenticated
}

// Updated handleClient to authenticate PIN for modify command
void handleClient(int clientSocket, SSL *ssl, sql::Connection *conn) {
    char buffer[1024];
    bzero(buffer, sizeof(buffer));

    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        SSL_write(ssl, "Error recieving data!\n", 22);
        return;
    }

    std::string request(buffer);
    std::istringstream iss(request);
    std::string command, account_number, pin, new_balance;

    iss >> command;

    if (command == "CREATE") {
        iss >> account_number >> pin;
        if (createAccount(account_number, pin, conn)) {
            SSL_write(ssl, "Account creation successful\n", 30);
        } else {
            SSL_write(ssl, "Account creation failed\n", 24);
        }
    } else if (command == "DELETE") {
        iss >> account_number >> pin;
        if (deleteAccount(account_number, pin, conn)) {
            SSL_write(ssl, "Account deletion successful\n", 30);
        } else {
            SSL_write(ssl, "Account deletion failed\n", 24);
        }
    } else if (command == "VIEW") {
        iss >> account_number;
        viewAccountDetails(account_number, conn, ssl);
    } else if (command == "MODIFY") {
        iss >> account_number >> pin >> new_balance;
        if (modifyAccountDetails(account_number, pin, new_balance, conn)) {
            SSL_write(ssl, "Account modification successful\n", 34);
        } else {
            SSL_write(ssl, "Account modification failed or authentication required\n", 56);
        }
    } else {
        SSL_write(ssl, "Unknown command\n", 16);
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
