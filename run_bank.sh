#!/bin/bash

# Compile the bank server
g++ -o bank bank.cpp -lmysqlcppconn

# Compile the atm client
g++ -o atm atm.cpp -lmysqlcppconn

# Run the bank server
./bank

# Run the ATM client
./atm
