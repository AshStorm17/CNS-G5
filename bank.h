#ifndef BANK_H
#define BANK_H

#include <cppconn/driver.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <string>

// Function to initialize the database (e.g., create tables if they don't exist)
void initializeDatabase(sql::Connection* conn);

// Function to add a customer
void addCustomer(sql::Connection* conn, const std::string& name, const std::string& account_number, const std::string& pin, double balance);

// Function to get the balance of a customer
double getBalance(sql::Connection* conn, const std::string& account_number);

// Function to update the balance (deposit or withdraw)
void updateBalance(sql::Connection* conn, const std::string& account_number, double amount, bool isDeposit);

// Function to authenticate a customer
bool authenticateCustomer(sql::Connection* conn, const std::string& account_number, const std::string& pin);

#endif // BANK_H
