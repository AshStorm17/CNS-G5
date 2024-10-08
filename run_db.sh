#!/bin/bash

# Auth file sent by the ATM
AUTH_FILE="bank.auth"
CONFIG_FILE="db_config.txt"

# Function to read configuration from the file
get_config_value() {
    grep -w "$1" "$CONFIG_FILE" | cut -d'=' -f2
}

# Function to read access permissions from auth file
get_permission_value() {
    grep -w "$1" "$AUTH_FILE" | cut -d'=' -f2
}

# Fetch database values from config file
DB_HOST=$(get_config_value host)
DB_PORT=$(get_config_value port)
DB_USER=$(get_config_value user)
DB_PASSWORD=$(get_config_value password)
DB_NAME=$(get_config_value database)

# Check if the auth file exists
if [ ! -f "$AUTH_FILE" ]; then
    echo "Error: Auth file not found. Access denied."
    exit 1
fi

# Get access permissions from the auth file
ACCESS_PERMISSION=$(get_permission_value access)

# Error handling for invalid access permissions
if [[ "$ACCESS_PERMISSION" != "read" && "$ACCESS_PERMISSION" != "write" ]]; then
    echo "Error: Invalid permissions in auth file. Access denied."
    exit 1
fi

# Command to access the database (usage examples)
COMMAND=$1
SQL_QUERY=$2

# If permission is read, only allow SELECT queries
if [[ "$ACCESS_PERMISSION" == "read" ]]; then
    if [[ $COMMAND != "query" ]]; then
        echo "Error: Write access is not permitted. Access denied."
        exit 1
    fi
fi

# Perform database operation
if [[ $COMMAND == "query" ]]; then
    echo "Executing query: $SQL_QUERY"
    mysql -u "$DB_USER" -p"$DB_PASSWORD" -h "$DB_HOST" -P "$DB_PORT" "$DB_NAME" -e "$SQL_QUERY"
else
    echo "Usage: $0 {query} \"SQL_QUERY\""
    exit 1
fi
