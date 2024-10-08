#!/bin/bash

# Default values
PORT=8080
AUTH_FILE="bank.auth"

# Parse command-line arguments for port (-p) and auth file (-s)
while getopts ":p:s:" opt; do
  case ${opt} in
    p )
      PORT=$OPTARG
      ;;
    s )
      AUTH_FILE=$OPTARG
      ;;
    \? )
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    : )
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Certificate Generation
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt

# Compile the bank server
g++ -std=c++11 bank.cpp -o bank.o -lssl -lcrypto -lmysqlcppconn -lpthread

# Run the bank server with the specified port and auth file
echo "Running bank server on port $PORT"
./bank.o -p "$PORT" -s "$AUTH_FILE"
