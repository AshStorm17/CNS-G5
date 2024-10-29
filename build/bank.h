#pragma once
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
#include <openssl/evp.h>
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
#include <mutex>
#include <jsoncpp/json/json.h>
#include <chrono> // Include this for timing
#include <thread> // Include this for sleep or delays

std::mutex db_mutex;

// Hash the pin using a secure hashing algorithm
std::string hashPin(const std::string& pin) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_length = 0;

    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, pin.c_str(), pin.length());
    EVP_DigestFinal_ex(ctx, hash, &hash_length);

    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hash_length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

// Authenticate the client by checking account_number and pin from the database
bool authenticateClient(const std::string& account_number, const std::string& pin, sql::Connection *conn) {
    std::lock_guard<std::mutex> lock(db_mutex);
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
bool createAccount(const std::string& account_number, const std::string& pin, sql::Connection *conn, const std::string& initial_deposit = "0") {
    std::lock_guard<std::mutex> lock(db_mutex);
    sql::PreparedStatement *pstmt;
    bool success = false;

    // Hash the pin securely
    std::string hashed_pin = hashPin(pin);

    // Prepare and execute SQL statement
    pstmt = conn->prepareStatement("INSERT INTO customers (account_number, pin, balance) VALUES (?, ?, ?)");
    pstmt->setString(1, account_number);
    pstmt->setString(2, hashed_pin);
    pstmt->setString(3, initial_deposit);

    try {
        pstmt->executeUpdate();
        success = true;
    } catch (sql::SQLException &e) {
        std::cerr << "Error creating account: " << e.what() << std::endl;
        throw std::runtime_error(std::string(e.what()));
    }

    delete pstmt;
    return success;
}

// Function to delete an account
bool deleteAccount(const std::string& account_number, const std::string& pin, sql::Connection *conn) {
    std::lock_guard<std::mutex> lock(db_mutex);
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
        throw std::runtime_error(std::string(e.what()));
    }

    delete pstmt;
    return success;
}

// Function to view account details
void viewAccountDetails(const std::string& account_number, const std::string& pin, sql::Connection *conn, SSL *ssl) {
    std::lock_guard<std::mutex> lock(db_mutex);
    sql::PreparedStatement *pstmt;
    sql::ResultSet *res;
    bool authenticated = false;

    std::string hashed_pin = hashPin(pin);

    pstmt = conn->prepareStatement("SELECT * FROM customers WHERE account_number = ?  AND pin = ?");
    pstmt->setString(1, account_number);
    pstmt->setString(2, hashed_pin);
    res = pstmt->executeQuery();

    if (res->next()) {
        authenticated = true;
    }

    delete res;
    delete pstmt;

    if (authenticated) {
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
    else{
        throw std::runtime_error("User authentication failed!");
    }
}

// Function to modify account details (e.g., update balance) with PIN authentication
bool depositAccountDetails(const std::string& account_number, const std::string& pin, const std::string& transac, sql::Connection *conn, SSL *ssl) {
    std::lock_guard<std::mutex> lock(db_mutex);
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
        // Retrieve the current balance from the database
        pstmt = conn->prepareStatement("SELECT balance FROM customers WHERE account_number = ?");
        pstmt->setString(1, account_number);
        res = pstmt->executeQuery();

        double old_balance = 0.0;
        if (res->next()) {
            old_balance = res->getDouble("balance");  // Retrieve the current balance
        }

        delete res;
        delete pstmt;

        // Convert new_balance to double and add it to the old balance
        double transac_double = std::stod(transac);  // Convert new_balance to double
        if(transac_double <= 0){
            std::cerr << "Invalid tranaction amount recieved." << std::endl;
            throw std::runtime_error("Invalid tranaction amount recieved.");
            return false;
        }

        double updated_balance = old_balance + transac_double;  // Add the old and new balance

        pstmt = conn->prepareStatement("UPDATE customers SET balance = ? WHERE account_number = ?");
        pstmt->setString(1, std::to_string(updated_balance));
        pstmt->setString(2, account_number);

        try {
            pstmt->executeUpdate();
            std::string transac_details = "Account number: "+ account_number + "\n";
            transac_details = transac_details + "Old Balance: " + std::to_string(old_balance) + "\n";
            transac_details = transac_details + "New Balance: " + std::to_string(updated_balance) + "\n";
            SSL_write(ssl, transac_details.c_str(), transac_details.size());
            delete pstmt; // Clean up after execution
            return true; // Modification successful
        } catch (sql::SQLException &e) {
            std::cerr << "Error modifying account details: " << e.what() << std::endl;
            throw std::runtime_error(std::string(e.what()));
        }

        delete pstmt; // Clean up if not authenticated or if error occurred
    }
    else{
        throw std::runtime_error("User authentication failed!");
    }
    return false; // Modification failed or not authenticated
}

// Function to withdraw from account with PIN authentication
bool withdrawAccountDetails(const std::string& account_number, const std::string& pin, const std::string& transac, sql::Connection *conn, SSL *ssl) {
    std::lock_guard<std::mutex> lock(db_mutex);
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

    // If authenticated, proceed to withdraw the amount
    if (authenticated) {
        // Retrieve the current balance from the database
        pstmt = conn->prepareStatement("SELECT balance FROM customers WHERE account_number = ?");
        pstmt->setString(1, account_number);
        res = pstmt->executeQuery();

        double old_balance = 0.0;
        if (res->next()) {
            old_balance = res->getDouble("balance");  // Retrieve the current balance
        }

        delete res;
        delete pstmt;

        // Convert the withdrawal amount to double
        double transac_double = std::stod(transac);  // Convert the transaction amount to double

        if(transac_double <= 0){
            std::cerr << "Invalid tranaction amount recieved." << std::endl;
            throw std::runtime_error("Invalid tranaction amount recieved.");
            return false;
        }

        // Check if there is enough balance for the withdrawal
        if (old_balance >= transac_double) {
            double updated_balance = old_balance - transac_double;  // Deduct the withdrawal amount

            // Update the balance in the database
            pstmt = conn->prepareStatement("UPDATE customers SET balance = ? WHERE account_number = ?");
            pstmt->setDouble(1, updated_balance);  // Set the updated balance
            pstmt->setString(2, account_number);

            try {
                pstmt->executeUpdate();
                std::string transac_details = "Account number: "+ account_number + "\n";
                transac_details = transac_details + "Old Balance: " + std::to_string(old_balance) + "\n";
                transac_details = transac_details + "New Balance: " + std::to_string(updated_balance) + "\n";
                SSL_write(ssl, transac_details.c_str(), transac_details.size());
                delete pstmt;  // Clean up after execution
                return true;  // Withdrawal successful
            } catch (sql::SQLException &e) {
                std::cerr << "Error modifying account details: " << e.what() << std::endl;
                throw std::runtime_error(std::string(e.what()));
            }
        } else {
            std::cerr << "Error: Insufficient funds. Cannot withdraw more than the current balance." << std::endl;
            throw std::runtime_error("Insufficient funds. Cannot withdraw more than the current balance.");
        }
    } else {
        throw std::runtime_error("User authentication failed!");
    }
    return false;  // Withdrawal failed or not authenticated
}


std::string generateHMAC(const std::string& message, const std::string& key) {
    unsigned char* result;
    unsigned int len = SHA256_DIGEST_LENGTH;

    result = HMAC(EVP_sha256(), key.c_str(), key.size(), 
                  (unsigned char*)message.c_str(), message.size(), NULL, NULL);

    // Convert the result to a hex string
    std::string hmac_result;
    for (unsigned int i = 0; i < len; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", result[i]);
        hmac_result.append(buf);
    }

    return hmac_result;
}

void handleClient(int clientSocket, SSL *ssl, sql::Connection *conn, std::string& auth_key) {
    char buffer[1024];
    bzero(buffer, sizeof(buffer));

    // Step 1: Read the request (JSON + HMAC) from the client (ATM)
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        SSL_write(ssl, "Error receiving data!\n", 22);
        return;
    }

    std::string received_message(buffer, bytes);
    
    // Step 2: Separate the JSON request and the HMAC
    size_t separator_pos = received_message.find("|");
    if (separator_pos == std::string::npos) {
        SSL_write(ssl, "Invalid message format. HMAC missing.\n", 38);
        return;
    }

    std::string json_request_str = received_message.substr(0, separator_pos);
    std::string received_hmac = received_message.substr(separator_pos + 1);

    // Step 3: Recompute the HMAC using the received JSON request and the shared auth_key
    std::string computed_hmac = generateHMAC(json_request_str, auth_key);

    // Step 4: Compare the received HMAC with the recomputed HMAC
    if (received_hmac != computed_hmac) {
        SSL_write(ssl, "Authentication failed: Invalid HMAC\n", 37);
        return;
    }

    // Step 5: Parse the JSON request after validating the HMAC
    Json::Value jsonRequest;
    Json::CharReaderBuilder reader;
    std::string errors;

    std::istringstream iss(json_request_str);
    if (!Json::parseFromStream(reader, iss, &jsonRequest, &errors)) {
        SSL_write(ssl, "Invalid JSON format\n", 20);
        return;
    }

    // Extract the operation from the JSON request
    std::string command = jsonRequest["operation"].asString();
    std::string account_number = jsonRequest["account"].asString();
    std::string pin = jsonRequest["pin_hash"].asString();

    // Define timeout duration (in seconds)
    const int timeout_duration = 10; // Example: 5 seconds

    // Start measuring time
    auto start_time = std::chrono::steady_clock::now();

    // Begin a transaction
    conn->setAutoCommit(false); // Disable auto-commit
    bool success = false; // Track success of operations    

    try {
        // Step 6: Process the request based on the command
        if (command == "CREATE") {
            std::string initial_balance = jsonRequest["initial_balance"].asString();
            success = createAccount(account_number, pin, conn, initial_balance);
            SSL_write(ssl, success ? "Account creation successful\n" : "Account creation failed\n", 30);
        } else if (command == "DELETE") {
            success = deleteAccount(account_number, pin, conn);
            SSL_write(ssl, success ? "Account deletion successful\n" : "Account deletion failed\n", 30);
        } else if (command == "GET_BALANCE") {
            viewAccountDetails(account_number, pin, conn, ssl);
            success = true; // Assume success for read operations
        } else if (command == "DEPOSIT") {
            std::string transac = jsonRequest["amount"].asString();
            success = depositAccountDetails(account_number, pin, transac, conn, ssl);
            SSL_write(ssl, success ? "Account modification successful\n" : "Account modification failed or authentication required\n", 56);
        } else if (command == "WITHDRAW") {
            std::string transac = jsonRequest["amount"].asString();
            success = withdrawAccountDetails(account_number, pin, transac, conn, ssl);
            SSL_write(ssl, success ? "Account modification successful\n" : "Account modification failed or authentication required\n", 56);
        } else {
            SSL_write(ssl, "Unknown command\n", 16);
        }

        // Check if the operation exceeded the timeout
        auto end_time = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed_seconds = end_time - start_time;

        if (elapsed_seconds.count() > timeout_duration) {
            throw std::runtime_error("Protocol error: Operation timed out");
        }

        // If everything is successful, commit the transaction
        if (success) {
            conn->commit();
        } else {
            throw std::runtime_error("Operation failed, rolling back");
        }
    } catch (const std::exception& e) {
        // Rollback if an error occurs
        conn->rollback();
        std::string error_msg = "Error occurred: " + std::string(e.what()) + "\n";
        SSL_write(ssl, error_msg.c_str(), error_msg.size());
    }
    
    // Ensure that auto-commit is re-enabled
    conn->setAutoCommit(true);
}


std::map<std::string, std::string> readConfig(const std::string& filename) {
    std::map<std::string, std::string> config;
    std::ifstream configFile(filename);
    std::string line;

    if (!configFile.is_open()) {
        std::cerr << "Unable to open config file!" << std::endl;
        return config;
    }

    while (std::getline(configFile, line)) {
        size_t delimiterPos = line.find('=');
        if (delimiterPos != std::string::npos) {
            std::string key = line.substr(0, delimiterPos);
            std::string value = line.substr(delimiterPos + 1);
            config[key] = value;
        }
    }
    configFile.close();
    return config;
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
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(255);
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 || 
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(255);
    }

    return ctx;
}

// Listen for incoming client connections over SSL
void listenForConnections(int port, const std::map<std::string, std::string>& auth, SSL_CTX* ctx, std::string& auth_key) {
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
            handleClient(clientSocket, ssl, conn, auth_key);
            conn->close();
            delete conn;
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);
    }
}

#endif // BANK_H
