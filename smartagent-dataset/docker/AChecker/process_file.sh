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

# Get the file extension
EXTENSION="${FILE##*.}"

# Check if the file extension is .sol
if [ "$EXTENSION" = "sol" ]; then
    # If the file is a Solidity file, use solc-select
    echo "processing $FILE"
    solc-select install $VERSION
    solc-select use $VERSION
    timeout 600 python bin/achecker.py -f $FILE -m 48
else
    echo "processing $FILE"
    # If the file is not a Solidity file, run the python command with the -b flag
    timeout 600 python bin/achecker.py -f $FILE -b -m 48
fi
