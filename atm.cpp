#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <jsoncpp/json/json.h>  // JSON library
#include <fstream> // Add this include for file handling
#include <random>  // Include for random number generation
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

void create_account(const string &account, float balance, const string &auth_file, const string &ip_address, int port, const string &card_file);
void deposit(const string &account, float amount, const string &auth_file, const string &ip_address, int port, const string &card_file);
void withdraw(const string &account, float amount, const string &auth_file, const string &ip_address, int port, const string &card_file);
void get_balance(const string &account, const string &auth_file, const string &ip_address, int port, const string &card_file);

int main(int argc, char *argv[]) {
    string account;
    string auth_file = "bank.auth";
    string ip_address = "127.0.1.1";
    int port = 8080;
    string card_file;
    float amount = 0;
    bool create_new = false, deposit_money = false, withdraw_money = false, get_balance_flag = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "-a") account = argv[++i];
        else if (arg == "-s") auth_file = argv[++i];
        else if (arg == "-i") ip_address = argv[++i];
        else if (arg == "-p") port = atoi(argv[++i]);
        else if (arg == "-c") card_file = argv[++i];
        else if (arg == "-n") { create_new = true; amount = atof(argv[++i]); }
        else if (arg == "-d") { deposit_money = true; amount = atof(argv[++i]); }
        else if (arg == "-w") { withdraw_money = true; amount = atof(argv[++i]); }
        else if (arg == "-g") get_balance_flag = true;
    }

    // Validate account name
    if (account.empty()) {
        cerr << "Account is required." << endl;
        return 255;
    }

    // Default card file
    if (card_file.empty()) {
        card_file = account + ".card";
    }

    // Execute operations
    if (create_new) create_account(account, amount, auth_file, ip_address, port, card_file);
    else if (deposit_money) deposit(account, amount, auth_file, ip_address, port, card_file);
    else if (withdraw_money) withdraw(account, amount, auth_file, ip_address, port, card_file);
    else if (get_balance_flag) get_balance(account, auth_file, ip_address, port, card_file);
    else {
        cerr << "Invalid operation. Exiting." << endl;
        return 255;
    }

    return 0;
}

void create_account(const string &account, float balance, const string &auth_file, const string &ip_address, int port, const string &card_file) {
    if (balance < 10.00) {
        cerr << "Initial balance must be at least 10.00." << endl;
        exit(255);
    }

    // Generate a random 16-digit PIN
    string pin;
    random_device rd; // Obtain a random number from hardware
    mt19937 eng(rd()); // Seed the generator
    uniform_int_distribution<> distr(1000, 9999); // Define the range

    for (int i = 0; i < 4; ++i) {
        pin += to_string(distr(eng)); // Generate 4 groups of 4 digits
    }

    // Remove the last character to avoid an extra digit
    pin.pop_back();

    // Write the PIN to the card file
    ofstream card_file_stream(card_file);
    if (card_file_stream) {
        card_file_stream << "PIN: " << pin << endl;
        card_file_stream.close();
    } else {
        cerr << "Error writing to card file." << endl;
        exit(255);
    }

    // // Establish a TCP connection to the bank server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        cerr << "Could not create socket." << endl;
        exit(255);
    }

    sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(ip_address.c_str());
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // Connect to the bank server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        cerr << "Connection failed." << endl;
        close(sock);
        exit(255);
    }

    // Create JSON message for account creation
    Json::Value request;
    request["command"] = "create";
    request["account"] = account;
    request["initial_balance"] = balance;
    request["auth_file"] = auth_file;

    Json::StreamWriterBuilder writer;
    string request_str = Json::writeString(writer, request);

    // Send message to server
    send(sock, request_str.c_str(), request_str.length(), 0);

    // Receive response
    char response[2000];
    int read_size = recv(sock, response, 2000, 0);
    if (read_size > 0) {
        cout << string(response, read_size) << endl;
    }

    close(sock);
}

void deposit(const string &account, float amount, const string &auth_file, const string &ip_address, int port, const string &card_file) {
    if (amount <= 0) {
        cerr << "Deposit amount must be greater than 0." << endl;
        exit(255);
    }

    // Establish TCP connection
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        cerr << "Could not create socket." << endl;
        exit(255);
    }

    sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(ip_address.c_str());
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        cerr << "Connection failed." << endl;
        close(sock);
        exit(255);
    }

    // Create JSON message for deposit
    Json::Value request;
    request["command"] = "deposit";
    request["account"] = account;
    request["amount"] = amount;
    request["auth_file"] = auth_file;
    request["card_file"] = card_file;

    Json::StreamWriterBuilder writer;
    string request_str = Json::writeString(writer, request);

    // Send message to server
    send(sock, request_str.c_str(), request_str.length(), 0);

    // Receive response
    char response[2000];
    int read_size = recv(sock, response, 2000, 0);
    if (read_size > 0) {
        cout << string(response, read_size) << endl;
    }

    close(sock);
}

void withdraw(const string &account, float amount, const string &auth_file, const string &ip_address, int port, const string &card_file) {
    if (amount <= 0) {
        cerr << "Withdraw amount must be greater than 0." << endl;
        exit(255);
    }

    // Establish TCP connection
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        cerr << "Could not create socket." << endl;
        exit(255);
    }

    sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(ip_address.c_str());
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        cerr << "Connection failed." << endl;
        close(sock);
        exit(255);
    }

    // Create JSON message for withdrawal
    Json::Value request;
    request["command"] = "withdraw";
    request["account"] = account;
    request["amount"] = amount;
    request["auth_file"] = auth_file;
    request["card_file"] = card_file;

    Json::StreamWriterBuilder writer;
    string request_str = Json::writeString(writer, request);

    // Send message to server
    send(sock, request_str.c_str(), request_str.length(), 0);

    // Receive response
    char response[2000];
    int read_size = recv(sock, response, 2000, 0);
    if (read_size > 0) {
        cout << string(response, read_size) << endl;
    }

    close(sock);
}

void get_balance(const string &account, const string &auth_file, const string &ip_address, int port, const string &card_file) {
    // Establish TCP connection
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        cerr << "Could not create socket." << endl;
        exit(255);
    }

    sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(ip_address.c_str());
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        cerr << "Connection failed." << endl;
        close(sock);
        exit(255);
    }

    // Create JSON message for balance inquiry
    Json::Value request;
    request["command"] = "balance";
    request["account"] = account;
    request["auth_file"] = auth_file;
    request["card_file"] = card_file;

    Json::StreamWriterBuilder writer;
    string request_str = Json::writeString(writer, request);

    // Send message to server
    send(sock, request_str.c_str(), request_str.length(), 0);

    // Receive response
    char response[2000];
    int read_size = recv(sock, response, 2000, 0);
    if (read_size > 0) {
        cout << string(response, read_size) << endl;
    }

    close(sock);
}