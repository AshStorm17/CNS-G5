#!/bin/bash

# Default values
AUTH_FILE="bank.yaml"
IP_ADDRESS="127.0.0.1"
PORT=3000
CARD_FILE=""
ACCOUNT=""
MODE=""
BALANCE=""

# Function to print usage and exit
usage() {
    echo "Usage: $0 -a <account> [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] <mode>"
    echo "Modes:"
    echo "  -n <balance>    Create a new account with the given balance."
    echo "  -d <amount>     Deposit the specified amount."
    echo "  -w <amount>     Withdraw the specified amount."
    echo "  -g              Get the current balance."
    exit 255
}


# Compile the atm server
g++ -std=c++11 atm.cpp -o atm.o -lssl -lcrypto -lmysqlcppconn -lpthread

# Parse command-line arguments
while getopts ":a:s:i:p:c:n:d:w:g" opt; do
    case ${opt} in
        a )
            ACCOUNT=$OPTARG
            ;;
        s )
            AUTH_FILE=$OPTARG
            ;;
        i )
            IP_ADDRESS=$OPTARG
            ;;
        p )
            PORT=$OPTARG
            ;;
        c )
            CARD_FILE=$OPTARG
            ;;
        n )
            MODE="-n"
            BALANCE=$OPTARG
            ;;
        d )
            MODE="-d"
            BALANCE=$OPTARG
            ;;
        w )
            MODE="-w"
            BALANCE=$OPTARG
            ;;
        g )
            MODE="-g"
            ;;
        \? )
            usage
            ;;
        : )
            echo "Option -$OPTARG requires an argument." >&2
            exit 255
            ;;
    esac
done

# Check mandatory parameters
if [ -z "$ACCOUNT" ] || [ -z "$MODE" ]; then
    usage
fi

# Set default values for card file if not specified
if [ -z "$CARD_FILE" ]; then
    CARD_FILE="${ACCOUNT}.card"
fi

# Prepare JSON response based on the mode of operation
json_response() {
    echo "{\"account\":\"$ACCOUNT\", \"$1\":$2}"
}

# Mode handling
case $MODE in
    -n)
        if [ -z "$BALANCE" ] || ! [[ "$BALANCE" =~ ^[0-9]+(\.[0-9]{1,2})?$ ]]; then
            exit 255
        fi

        # Check if the account already exists
        if [ -f "$CARD_FILE" ]; then
            exit 255
        fi

        if (( $(echo "$BALANCE < 10.00" | bc -l) )); then
            exit 255
        fi

        # Create a new account (simulate with curl or other methods)
        RESPONSE=$(curl -s -X POST "http://$IP_ADDRESS:$PORT/create" -d "account=$ACCOUNT&balance=$BALANCE&card_file=$CARD_FILE" -o /dev/null -w "%{http_code}")
        if [ "$RESPONSE" -ne 200 ]; then
            exit 255
        fi

        # Create the card file
        touch "$CARD_FILE"
        json_response "initial_balance" "$BALANCE"
        ;;

    -d)
        if [ -z "$BALANCE" ] || ! [[ "$BALANCE" =~ ^[0-9]+(\.[0-9]{1,2})?$ ]]; then
            exit 255
        fi

        # Simulate deposit
        RESPONSE=$(curl -s -X POST "http://$IP_ADDRESS:$PORT/deposit" -d "account=$ACCOUNT&amount=$BALANCE&card_file=$CARD_FILE" -o /dev/null -w "%{http_code}")
        if [ "$RESPONSE" -ne 200 ]; then
            exit 255
        fi

        json_response "deposit" "$BALANCE"
        ;;

    -w)
        if [ -z "$BALANCE" ] || ! [[ "$BALANCE" =~ ^[0-9]+(\.[0-9]{1,2})?$ ]]; then
            exit 255
        fi

        # Simulate withdrawal
        RESPONSE=$(curl -s -X POST "http://$IP_ADDRESS:$PORT/withdraw" -d "account=$ACCOUNT&amount=$BALANCE&card_file=$CARD_FILE" -o /dev/null -w "%{http_code}")
        if [ "$RESPONSE" -ne 200 ]; then
            exit 255
        fi

        json_response "withdraw" "$BALANCE"
        ;;

    -g)
        # Simulate balance inquiry
        RESPONSE=$(curl -s -X GET "http://$IP_ADDRESS:$PORT/balance?account=$ACCOUNT&card_file=$CARD_FILE" -o response.json)
        if [ $? -ne 0 ]; then
            exit 255
        fi

        # Print the response
        cat response.json
        rm response.json
        ;;

    *)
        exit 255
        ;;
esac

exit 0
