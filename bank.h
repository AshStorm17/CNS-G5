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
#include <sstream>

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

// Listen for incoming client connections
void listenForConnections(int port, const std::map<std::string, std::string>& auth) {
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
        std::cout << "Client connected." << std::endl;
        sql::Connection *conn = initDatabaseConnection(auth);
        handleClient(clientSocket, conn);
        delete conn;
    }
}

// Handle client requests
void handleClient(int clientSocket, sql::Connection *conn) {
    char buffer[1024];
    bzero(buffer, 1024);

    // Receive client data (e.g., account number and PIN for authentication)
    recv(clientSocket, buffer, 1024, 0);
    std::string account_number, pin;
    
    // Extract account_number and pin (assuming a simple format "account_number pin")
    std::istringstream iss(buffer);
    iss >> account_number >> pin;

    if (authenticateClient(account_number, pin, conn)) {
        std::string response = "Authentication successful\n";
        send(clientSocket, response.c_str(), response.size(), 0);
    } else {
        std::string response = "Authentication failed\n";
        send(clientSocket, response.c_str(), response.size(), 0);
    }

    close(clientSocket);
}

// Authenticate the client by checking account_number and pin from the database
bool authenticateClient(const std::string& account_number, const std::string& pin, sql::Connection *conn) {
    sql::PreparedStatement *pstmt;
    sql::ResultSet *res;
    bool authenticated = false;

    pstmt = conn->prepareStatement("SELECT * FROM customers WHERE account_number = ? AND pin = ?");
    pstmt->setString(1, account_number);
    pstmt->setString(2, pin);
    res = pstmt->executeQuery();

    if (res->next()) {
        authenticated = true;
    }

    delete res;
    delete pstmt;
    return authenticated;
}

#endif // BANK_H
