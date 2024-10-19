#include <iostream>
#include <fstream>
#include <map>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

// Function to read configuration from a file
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

int main() {
    try {
        // Read MySQL credentials from config file
        std::map<std::string, std::string> config = readConfig("db_config.txt");

        // Create a MySQL driver instance
        sql::mysql::MySQL_Driver* driver;
        sql::Connection* conn;
        sql::Statement* stmt;
        sql::ResultSet* res;

        // Get the MySQL driver
        driver = sql::mysql::get_mysql_driver_instance();

        // Connect to the MySQL database using the config details
        std::string host = "tcp://" + config["host"] + ":" + config["port"];
        conn = driver->connect(host, config["user"], config["password"]);

        // Connect to the specific database
        conn->setSchema(config["database"]);

        // Create a statement
        stmt = conn->createStatement();

        // Execute a query and fetch the results
        res = stmt->executeQuery("SELECT * FROM customers");

        // Process the result set
        while (res->next()) {
            std::cout << "ID: " << res->getInt("id") << std::endl;
            std::cout << "Account Number: " << res->getString("account_number") << std::endl;
            std::cout << "Balance: " << res->getDouble("balance") << std::endl;
            std::cout << "PIN: " << res->getString("pin") << std::endl;
        }

        // Clean up
        delete res;
        delete stmt;
        delete conn;

    } catch (sql::SQLException &e) {
        std::cerr << "SQLException: " << e.what() << std::endl;
        std::cerr << "MySQL error code: " << e.getErrorCode() << std::endl;
        std::cerr << "SQLState: " << e.getSQLState() << std::endl;
    }
}
