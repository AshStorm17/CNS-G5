# Symlink names
BANK_SYMLINK = bank
ATM_SYMLINK = atm

# Variables for DB initialization
DB_CONFIG_FILE = db_config.txt
INIT_DB_SCRIPT = init_db.sql

# Rule to read the password from the config file (helper function)
get_db_config = $(shell awk -F '=' '/^$(1)=/ {print $$2}' $(DB_CONFIG_FILE))

# Extract credentials from config file
DB_HOST := $(call get_db_config,host)
DB_PORT := $(call get_db_config,port)
DB_USER := $(call get_db_config,user)
DB_PASSWORD := $(call get_db_config,password)
DB_NAME := $(call get_db_config,database)

# Rule to create symlinks for easy execution
.PHONY: symlink
symlink:
	ln -sf run_bank.sh $(BANK_SYMLINK)
	ln -sf run_atm.sh $(ATM_SYMLINK)

# Rule to create the database if it doesn't exist
.PHONY: createdb
createdb:
	@echo "Creating the database if it doesn't exist..."
	@mysql -u $(DB_USER) -p'$(DB_PASSWORD)' -h $(DB_HOST) -P $(DB_PORT) -e "CREATE DATABASE IF NOT EXISTS $(DB_NAME);"

# Rule to initialize the database
.PHONY: initdb
initdb: createdb
	@echo "Initializing the database..."
	@mysql -u $(DB_USER) -p'$(DB_PASSWORD)' -h $(DB_HOST) -P $(DB_PORT) $(DB_NAME) < $(INIT_DB_SCRIPT)

# Rule to drop the database
.PHONY: dropdb
dropdb:
	@echo "Dropping the database..."
	@mysql -u $(DB_USER) -p'$(DB_PASSWORD)' -h $(DB_HOST) -P $(DB_PORT) -e "DROP DATABASE IF EXISTS $(DB_NAME);"

# Clean up symlinks
clean:
	rm -f $(BANK_SYMLINK) $(ATM_SYMLINK)

# Combined rule to create symlinks
all: symlink
