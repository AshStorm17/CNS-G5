#include <iostream>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>

// Function to display menu
void displayMenu() {
    std::cout << "1. Deposit" << std::endl;
    std::cout << "2. Withdraw" << std::endl;
    std::cout << "3. Check Balance" << std::endl;
    std::cout << "4. Exit" << std::endl;
}

int main() {
    try {
        sql::mysql::MySQL_Driver* driver;
        sql::Connection* conn;
        sql::PreparedStatement* pstmt;
        sql::ResultSet* res;

        // MySQL connection details from config file
        driver = sql::mysql::get_mysql_driver_instance();
        conn = driver->connect("tcp://127.0.0.1:3306", "root", "password");

        conn->setSchema("atm_bank_db");

        std::string accountNumber;
        std::string pin;

        std::cout << "Welcome to ATM!" << std::endl;
        std::cout << "Enter your account number: ";
        std::cin >> accountNumber;
        std::cout << "Enter your PIN: ";
        std::cin >> pin;

        // Authenticate user
        pstmt = conn->prepareStatement("SELECT balance FROM customers WHERE account_number=? AND pin=?");
        pstmt->setString(1, accountNumber);
        pstmt->setString(2, pin);
        res = pstmt->executeQuery();

        if (res->next()) {
            double balance = res->getDouble("balance");
            std::cout << "Login successful. Your current balance is: " << balance << std::endl;

            int choice;
            double amount;
            while (true) {
                displayMenu();
                std::cout << "Choose an option: ";
                std::cin >> choice;

                switch (choice) {
                    case 1: // Deposit
                        std::cout << "Enter amount to deposit: ";
                        std::cin >> amount;
                        pstmt = conn->prepareStatement("UPDATE customers SET balance = balance + ? WHERE account_number = ?");
                        pstmt->setDouble(1, amount);
                        pstmt->setString(2, accountNumber);
                        pstmt->executeUpdate();
                        std::cout << "Deposit successful!" << std::endl;
                        break;
                    case 2: // Withdraw
                        std::cout << "Enter amount to withdraw: ";
                        std::cin >> amount;
                        pstmt = conn->prepareStatement("SELECT balance FROM customers WHERE account_number=?");
                        pstmt->setString(1, accountNumber);
                        res = pstmt->executeQuery();
                        if (res->next() && res->getDouble("balance") >= amount) {
                            pstmt = conn->prepareStatement("UPDATE customers SET balance = balance - ? WHERE account_number = ?");
                            pstmt->setDouble(1, amount);
                            pstmt->setString(2, accountNumber);
                            pstmt->executeUpdate();
                            std::cout << "Withdrawal successful!" << std::endl;
                        } else {
                            std::cout << "Insufficient balance." << std::endl;
                        }
                        break;
                    case 3: // Check balance
                        pstmt = conn->prepareStatement("SELECT balance FROM customers WHERE account_number=?");
                        pstmt->setString(1, accountNumber);
                        res = pstmt->executeQuery();
                        if (res->next()) {
                            std::cout << "Current balance: " << res->getDouble("balance") << std::endl;
                        }
                        break;
                    case 4: // Exit
                        std::cout << "Goodbye!" << std::endl;
                        delete pstmt;
                        delete res;
                        delete conn;
                        return 0;
                }
            }
        } else {
            std::cout << "Authentication failed!" << std::endl;
        }

    } catch (sql::SQLException &e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        std::cerr << "MySQL error code: " << e.getErrorCode() << std::endl;
        std::cerr << "SQLState: " << e.getSQLState() << std::endl;
    }
    return 0;
}
