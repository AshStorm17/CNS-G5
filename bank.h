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
    }

    delete pstmt;
    return success;
}

// Function to view account details
void viewAccountDetails(const std::string& account_number, sql::Connection *conn, SSL *ssl) {
    std::lock_guard<std::mutex> lock(db_mutex);
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
bool depositAccountDetails(const std::string& account_number, const std::string& pin, const std::string& transac, sql::Connection *conn) {
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
        double updated_balance = old_balance + transac_double;  // Add the old and new balance

        pstmt = conn->prepareStatement("UPDATE customers SET balance = ? WHERE account_number = ?");
        pstmt->setString(1, std::to_string(updated_balance));
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

// Function to withdraw from account with PIN authentication
bool withdrawAccountDetails(const std::string& account_number, const std::string& pin, const std::string& transac, sql::Connection *conn) {
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

        // Check if there is enough balance for the withdrawal
        if (old_balance >= transac_double) {
            double updated_balance = old_balance - transac_double;  // Deduct the withdrawal amount

            // Update the balance in the database
            pstmt = conn->prepareStatement("UPDATE customers SET balance = ? WHERE account_number = ?");
            pstmt->setDouble(1, updated_balance);  // Set the updated balance
            pstmt->setString(2, account_number);

            try {
                pstmt->executeUpdate();
                delete pstmt;  // Clean up after execution
                return true;  // Withdrawal successful
            } catch (sql::SQLException &e) {
                std::cerr << "Error modifying account details: " << e.what() << std::endl;
            }
        } else {
            std::cerr << "Error: Insufficient funds. Cannot withdraw more than the current balance." << std::endl;
        }
    }

    delete pstmt;  // Clean up if not authenticated or if error occurred
    return false;  // Withdrawal failed or not authenticated
}


// Updated handleClient to authenticate PIN for modify command
void handleClient(int clientSocket, SSL *ssl, sql::Connection *conn) {
    char buffer[1024];
    bzero(buffer, sizeof(buffer));

    // Read the request from the client (ATM)
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        SSL_write(ssl, "Error receiving data!\n", 22);
        return;
    }

    // Parse the received JSON request
    std::string request(buffer);
    Json::Value jsonRequest;
    Json::CharReaderBuilder reader;
    std::string errors;

    // Create an input stream from the request string
    std::istringstream iss(request);

    // Now pass the lvalue (iss) to parseFromStream
    if (!Json::parseFromStream(reader, iss, &jsonRequest, &errors)) {
        SSL_write(ssl, "Invalid JSON format\n", 20);
        return;
    }

    // Extract the operation from the JSON request
    std::string command = jsonRequest["operation"].asString();
    std::string account_number = jsonRequest["account"].asString();
    std::string pin = "1010";
    if (command == "CREATE") {
        if (createAccount(account_number, pin, conn)) {
            SSL_write(ssl, "Account creation successful\n", 30);
        } else {
            SSL_write(ssl, "Account creation failed\n", 24);
        }
    } else if (command == "DELETE") {
        if (deleteAccount(account_number, pin, conn)) {
            SSL_write(ssl, "Account deletion successful\n", 30);
        } else {
            SSL_write(ssl, "Account deletion failed\n", 24);
        }
    } else if (command == "VIEW") {
        viewAccountDetails(account_number, conn, ssl);
    } else if (command == "DEPOSIT") {
        std::string transac = jsonRequest["amount"].asString();
        if (depositAccountDetails(account_number, pin, transac, conn)) {
            SSL_write(ssl, "Account modification successful\n", 34);
        } else {
            SSL_write(ssl, "Account modification failed or authentication required\n", 56);
        }
    } else if (command == "WITHDRAW") {
        std::string transac = jsonRequest["amount"].asString();
        if (withdrawAccountDetails(account_number, pin, transac, conn)) {
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
    const SSL_METHOD *method = TLS_server_method();
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
            conn->close();
            delete conn;
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);
    }
}


#endif // BANK_H
