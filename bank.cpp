#include "bank.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <stdexcept>

// Function to load credentials from auth.txt
std::map<std::string, std::string> loadAuthDetails(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open authentication file.");
    }

    std::map<std::string, std::string> authDetails;
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            authDetails[key] = value;
        }
    }

    file.close();
    return authDetails;
}

// Initialize database (e.g., create tables if they don't exist)
void initializeDatabase(sql::Connection* conn) {
    sql::Statement* stmt = conn->createStatement();
    stmt->execute("CREATE TABLE IF NOT EXISTS customers ("
                  "id INT AUTO_INCREMENT PRIMARY KEY, "
                  "name VARCHAR(255), "
                  "account_number VARCHAR(20), "
                  "pin VARCHAR(20), "
                  "balance DOUBLE)");
    delete stmt;
}

// Add a new customer to the database
void addCustomer(sql::Connection* conn, const std::string& name, const std::string& account_number, const std::string& pin, double balance) {
    sql::PreparedStatement* pstmt = conn->prepareStatement("INSERT INTO customers (name, account_number, pin, balance) VALUES (?, ?, ?, ?)");
    pstmt->setString(1, name);
    pstmt->setString(2, account_number);
    pstmt->setString(3, pin);
    pstmt->setDouble(4, balance);
    pstmt->executeUpdate();
    delete pstmt;
}

// Get the balance of a customer by account number
double getBalance(sql::Connection* conn, const std::string& account_number) {
    sql::PreparedStatement* pstmt = conn->prepareStatement("SELECT balance FROM customers WHERE account_number = ?");
    pstmt->setString(1, account_number);
    sql::ResultSet* res = pstmt->executeQuery();
    double balance = 0.0;
    if (res->next()) {
        balance = res->getDouble("balance");
    }
    delete res;
    delete pstmt;
    return balance;
}

// Update balance of a customer (deposit/withdraw)
void updateBalance(sql::Connection* conn, const std::string& account_number, double amount, bool isDeposit) {
    double currentBalance = getBalance(conn, account_number);
    double newBalance = isDeposit ? currentBalance + amount : currentBalance - amount;

    sql::PreparedStatement* pstmt = conn->prepareStatement("UPDATE customers SET balance = ? WHERE account_number = ?");
    pstmt->setDouble(1, newBalance);
    pstmt->setString(2, account_number);
    pstmt->executeUpdate();
    delete pstmt;
}

// Authenticate customer using account number and pin
bool authenticateCustomer(sql::Connection* conn, const std::string& account_number, const std::string& pin) {
    sql::PreparedStatement* pstmt = conn->prepareStatement("SELECT pin FROM customers WHERE account_number = ?");
    pstmt->setString(1, account_number);
    sql::ResultSet* res = pstmt->executeQuery();
    bool isAuthenticated = false;
    if (res->next()) {
        isAuthenticated = (res->getString("pin") == pin);
    }
    delete res;
    delete pstmt;
    return isAuthenticated;
}

// Main function to test bank functionality
int main() {
    try {
        // Load credentials from auth.txt
        std::map<std::string, std::string> auth = loadAuthDetails("auth.txt");

        // Connect to the MySQL server using the credentials
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
        sql::Connection* conn = driver->connect(auth["host"], auth["user"], auth["password"]);

        // Select the database
        conn->setSchema(auth["database"]);

        // Initialize the bank database and create tables if needed
        initializeDatabase(conn);

        // Sample usage: Adding a customer
        addCustomer(conn, "John Doe", "123456789", "1234", 500.0);

        // Sample usage: Retrieve customer balance
        double balance = getBalance(conn, "123456789");
        std::cout << "Customer balance: $" << balance << std::endl;

        // Sample usage: Update balance (deposit)
        updateBalance(conn, "123456789", 100.0, true);

        // Authenticate customer
        if (authenticateCustomer(conn, "123456789", "1234")) {
            std::cout << "Customer authenticated successfully." << std::endl;
        } else {
            std::cout << "Authentication failed." << std::endl;
        }

        // Close the connection
        delete conn;
    } catch (sql::SQLException &e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
    } catch (std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
