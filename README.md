# CNS-G5

## About
The project involves developing two main components: an ATM client (atm) and a Bank server (bank), which will communicate securely over a network. The ATM client interacts with the Bank server to update or query customer account balances. Security measures are in place to prevent unauthorized access and ensure data integrity during transactions.


## Project Overview
This project implements a secure Bank and ATM system with various functionalities, including account creation, balance inquiry, deposit, and withdrawal. The system uses C++ and integrates OpenSSL for encryption, MySQL Connector for database interaction, and multi-threading using pthreads. It provides two components:
1. **Bank Server**: Manages user accounts, including balance management.
2. **ATM Client**: Interacts with the bank server to create accounts, deposit, withdraw, and check balances.


## Installations
```
sudo apt-get update
sudo apt-get install g++ libssl-dev libmysqlcppconn-dev libcurl4-openssl-dev libpthread-stubs0-dev
```


## Database (for bank)
Before running the initialization command, make sure your database credentials are correctly set in the configuration file
```
make initdb
```


## Bank
The bank.cpp handles the server-side functionality, including certificate generation and processing transactions.

```
make bank
```
```
./bank -p <port> -s <auth_file>
```

## ATM
The atm.cpp is the client-side application that communicates with the bank server. The script run_atm.sh is used to compile and execute the ATM client.
```
./atm -a <account> [-s <auth_file>] [-i <ip_address>] [-p <port>] [-c <card_file>] <mode>
```


## Team Members

| Name             | Roll Number |
|------------------|-------------|
| Aashmun Gupta    | 22110005    |
| Aryan Sahu       | 22110038    |
| Aayush Parmar    | 22110181    |
| Mrugank Patil    | 22110158    |
| Arjun Sekar      | 22110034    |
| Pratyaksh Bhayre | 22110       |
