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

void create_account(const string &account, float balance, const string &auth_file, const string &ip_address, int port, const string &card_file, SSL_CTX *ctx);
void deposit(const string &account, float amount, const string &auth_file, const string &ip_address, int port, const string &card_file, SSL_CTX *ctx);
void withdraw(const string &account, float amount, const string &auth_file, const string &ip_address, int port, const string &card_file, SSL_CTX *ctx);
void get_balance(const string &account, const string &auth_file, const string &ip_address, int port, const string &card_file, SSL_CTX *ctx);


SSL_CTX* InitSSLContext() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());  // Create a new SSL context
    if (!ctx) {
        cerr << "Unable to create SSL context" << endl;
        exit(EXIT_FAILURE);
    }

    // Load client certificates
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", nullptr)) {
        cerr << "Error loading certificate file" << endl;
        exit(EXIT_FAILURE);
    }

    return ctx;
}

SSL* ConnectToBank(const string &ip_address, int port, SSL_CTX *ctx) {
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

    // Create an SSL object for the socket
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        cerr << "SSL connection failed" << endl;
        close(sock);
        SSL_free(ssl);
        exit(255);
    }

    return ssl;
}

void CloseSSLConnection(SSL *ssl) {
    int sock = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
}

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

    // Initialize SSL context
    SSL_CTX *ctx = InitSSLContext();

    // Execute operations
    if (create_new) create_account(account, amount, auth_file, ip_address, port, card_file, ctx);
    else if (deposit_money) deposit(account, amount, auth_file, ip_address, port, card_file, ctx);
    else if (withdraw_money) withdraw(account, amount, auth_file, ip_address, port, card_file, ctx);
    else if (get_balance_flag) get_balance(account, auth_file, ip_address, port, card_file, ctx);
    else {
        cerr << "Invalid operation. Exiting." << endl;
        return 255;
    }

    return 0;

    // Cleanup SSL context
    SSL_CTX_free(ctx);
    return 0;
}

void create_account(const string &account, float balance, const string &auth_file, const string &ip_address, int port, const string &card_file, SSL_CTX *ctx) {
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

    SSL *ssl = ConnectToBank(ip_address, port, ctx);

    // Create JSON message for account creation
    Json::Value request;
    request["command"] = "create";
    request["account"] = account;
    request["initial_balance"] = balance;
    request["auth_file"] = auth_file;

    Json::StreamWriterBuilder writer;
    string request_str = Json::writeString(writer, request);

    // Send message to server using SSL
    SSL_write(ssl, request_str.c_str(), request_str.length());

    // Receive response
    char response[2000];
    int read_size = SSL_read(ssl, response, 2000);
    if (read_size > 0) {
        cout << string(response, read_size) << endl;
    }

    CloseSSLConnection(ssl);
}

void deposit(const string &account, float amount, const string &auth_file, const string &ip_address, int port, const string &card_file, SSL_CTX *ctx) {
    if (amount <= 0) {
        cerr << "Deposit amount must be greater than 0." << endl;
        exit(255);
    }

    
    SSL *ssl = ConnectToBank(ip_address, port, ctx);

    // Create JSON message for deposit
    Json::Value request;
    request["command"] = "deposit";
    request["account"] = account;
    request["amount"] = amount;
    request["auth_file"] = auth_file;
    request["card_file"] = card_file;

    Json::StreamWriterBuilder writer;
    string request_str = Json::writeString(writer, request);

    // Send message to server using SSL
    SSL_write(ssl, request_str.c_str(), request_str.length());

    // Receive response
    char response[2000];
    int read_size = SSL_read(ssl, response, 2000);
    if (read_size > 0) {
        cout << string(response, read_size) << endl;
    }

    CloseSSLConnection(ssl);
}

void withdraw(const string &account, float amount, const string &auth_file, const string &ip_address, int port, const string &card_file, SSL_CTX *ctx) {
    if (amount <= 0) {
        cerr << "Withdraw amount must be greater than 0." << endl;
        exit(255);
    }

    SSL *ssl = ConnectToBank(ip_address, port, ctx);

    // Create JSON message for withdrawal
    Json::Value request;
    request["command"] = "withdraw";
    request["account"] = account;
    request["amount"] = amount;
    request["auth_file"] = auth_file;
    request["card_file"] = card_file;

    Json::StreamWriterBuilder writer;
    string request_str = Json::writeString(writer, request);

    // Send message to server using SSL
    SSL_write(ssl, request_str.c_str(), request_str.length());

    // Receive response
    char response[2000];
    int read_size = SSL_read(ssl, response, 2000);
    if (read_size > 0) {
        cout << string(response, read_size) << endl;
    }

    CloseSSLConnection(ssl);
}

void get_balance(const string &account, const string &auth_file, const string &ip_address, int port, const string &card_file, SSL_CTX *ctx) {
    SSL *ssl = ConnectToBank(ip_address, port, ctx);

    // Create JSON message for balance inquiry
    Json::Value request;
    request["command"] = "balance";
    request["account"] = account;
    request["auth_file"] = auth_file;
    request["card_file"] = card_file;

    Json::StreamWriterBuilder writer;
    string request_str = Json::writeString(writer, request);

    // Send message to server using SSL
    SSL_write(ssl, request_str.c_str(), request_str.length());

    // Receive response
    char response[2000];
    int read_size = SSL_read(ssl, response, 2000);
    if (read_size > 0) {
        cout << string(response, read_size) << endl;
    }

    CloseSSLConnection(ssl);
}