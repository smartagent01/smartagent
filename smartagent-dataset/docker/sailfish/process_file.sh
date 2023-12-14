#!/bin/bash

# Check if exactly two arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <file> <solc-version>"
    echo "Example: $0 /path/to/yourfile.sol 0.8.0"
    exit 1
fi

# Assign arguments to variables for clarity
FILE=$1
VERSION=$2

# If the file is a Solidity file, use solc-select
echo "processing $FILE"
solc-select install $VERSION
solc-select use $VERSION
python contractlint.py -c $FILE -o ./ -r havoc -p DAO -oo -sv cvc4

