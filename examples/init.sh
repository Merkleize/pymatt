#!/bin/bash

# Set bitcoin-cli with regtest option as a variable for simplicity
BITCOIN_CLI="bitcoin-cli -regtest"

# Try to create the wallet "testwallet"
WALLET_CREATE_RESULT=$($BITCOIN_CLI createwallet "testwallet" 2>&1)

# If the wallet already exists, load it
if [[ $WALLET_CREATE_RESULT == *"Database already exists"* ]]; then
    echo "Wallet 'testwallet' already exists. Loading it..."
    $BITCOIN_CLI loadwallet "testwallet"
fi

# Get a new address from "testwallet"
NEW_ADDRESS=$($BITCOIN_CLI getnewaddress)

# Check for valid address before proceeding
if [[ -z $NEW_ADDRESS ]]; then
    echo "Failed to get a new address."
    exit 1
fi

# Generate 101 blocks, sending the block reward to the new address
$BITCOIN_CLI generatetoaddress 110 $NEW_ADDRESS

echo "Generated 101 blocks to address: $NEW_ADDRESS"
