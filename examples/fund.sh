#!/bin/bash

# Check if at least one argument (Bitcoin address) was provided
if [ "$#" -lt 1 ]; then
    echo "Usage: ./fund.sh <bitcoin_address> [amount]"
    exit 1
fi

# Set the address to the provided argument
ADDRESS=$1

# Check if an amount was provided; if not, default to 0.002
AMOUNT=${2:-0.00002}

# Send the specified amount (or 0.0002 if none specified) to the provided address
bitcoin-cli -regtest sendtoaddress $ADDRESS $AMOUNT

# Generate a block to confirm the transaction
bitcoin-cli -regtest -generate 1
