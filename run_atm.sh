#!/bin/bash

# Default values
AUTH_FILE="bank.auth"
IP_ADDRESS="127.0.0.1"
PORT=3000
CARD_FILE=""
ACCOUNT=""
AMOUNT=""
MODE=""  # For the operation mode (-n, -g, -d, or -w)

# Function to display usage information
usage() {
    echo "Usage: $0 [-s auth_file] [-i ip_address] [-p port] [-c card_file] -a account -n|-g|-d|-w amount"
    exit 1
}

# Compile the atm server
g++ -std=c++11 atm.cpp -o atm.o -lssl -lcrypto -lmysqlcppconn -lpthread -ljsoncpp -Wno-deprecated-declarations

# Parse command-line arguments
while getopts "s:i:p:c:a:n:gd:w:" opt; do
  case $opt in
    s) AUTH_FILE="$OPTARG" ;;      # Optional: Set auth file
    i) IP_ADDRESS="$OPTARG" ;;     # Optional: Set IP address
    p) PORT="$OPTARG" ;;           # Optional: Set port
    c) CARD_FILE="$OPTARG" ;;      # Optional: Set card file
    a) ACCOUNT="$OPTARG" ;;        # Required: Set account
    n) LAST_OPTION="-n $OPTARG"; AMOUNT="$OPTARG"; MODE="n" ;;  # Mode -n with amount
    g) LAST_OPTION="-g"; MODE="g" ;;                             # Mode -g (no amount)
    d) LAST_OPTION="-d $OPTARG"; AMOUNT="$OPTARG"; MODE="d" ;;  # Mode -d with amount
    w) LAST_OPTION="-w $OPTARG"; AMOUNT="$OPTARG"; MODE="w" ;;  # Mode -w with amount
    \?) usage ;;  # Display usage if an invalid option is provided
  esac
done

# Check mandatory parameters
if [ -z "$ACCOUNT" ] || [ -z "$MODE" ]; then
    echo "Error: -a (account) and one of -n, -g, -d, or -w (mode) are required."
    usage
fi

# Set default card file if not specified
if [ -z "$CARD_FILE" ]; then
    CARD_FILE="${ACCOUNT}.card"
fi

# Execute the bank.o command
./atm.o -s "$AUTH_FILE" -i "$IP_ADDRESS" -p "$PORT" -c "$CARD_FILE" -a "$ACCOUNT" "$LAST_OPTION"
