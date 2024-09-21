# Symlink names
BANK_SYMLINK = bank
ATM_SYMLINK = atm

# Rule to create symlinks for easy execution
.PHONY: symlink
symlink:
	ln -sf run_bank.sh $(BANK_SYMLINK)
	ln -sf run_atm.sh $(ATM_SYMLINK)

# Clean up symlinks
clean:
	rm -f $(BANK_SYMLINK) $(ATM_SYMLINK)

# Combined rule to create symlinks
all: symlink
