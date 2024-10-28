USE atm_bank_db;

CREATE TABLE customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    account_number VARCHAR(255) UNIQUE,
    balance DOUBLE NOT NULL,
    pin VARCHAR(255)
);