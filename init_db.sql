CREATE DATABASE atm_bank_db;
USE atm_bank_db;

CREATE TABLE customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    account_number VARCHAR(20) UNIQUE,
    balance DOUBLE NOT NULL,
    pin VARCHAR(100)
);

INSERT INTO customers (name, account_number, balance, pin) VALUES 
('Alice Smith', '0987654321', 1500.0, 'hashed_pin_value_1'),
('Bob Johnson', '1122334455', 2000.0, 'hashed_pin_value_2'),
('Charlie Brown', '2233445566', 2500.0, 'hashed_pin_value_3'),
('Diana Prince', '3344556677', 3000.0, 'hashed_pin_value_4'),
('Edward Elric', '4455667788', 3500.0, 'hashed_pin_value_5'),
('Fiona Glenanne', '5566778899', 4000.0, 'hashed_pin_value_6'),
('George Miller', '6677889900', 4500.0, 'hashed_pin_value_7'),
('Hannah Montana', '7788990011', 5000.0, 'hashed_pin_value_8'),
('Ian Malcolm', '8899001122', 5500.0, 'hashed_pin_value_9'),
('Jane Doe', '9900112233', 6000.0, 'hashed_pin_value_10');