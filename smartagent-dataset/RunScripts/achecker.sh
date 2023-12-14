#!/bin/bash
# run Achecker
# sample : ./achecker.sh test.bin-runtime 0.1.2 600
# Check if there are at least 3 arguments
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <file-path> <solc-version> <timeout>"
    exit 1
fi

# Convert the relative file path to an absolute path
FILE_PATH=$(realpath "$1")

# Define the path inside the container where the file will be copied
CONTAINER_FILE_PATH="/root/Achecker/$(basename "$FILE_PATH")"

# Create a new Docker container without starting it
CONTAINER_ID=$(docker create achecker "$CONTAINER_FILE_PATH" "$2")

# Copy the file into the container at the specified path
docker cp "$FILE_PATH" "${CONTAINER_ID}:${CONTAINER_FILE_PATH}"
echo "File copied : $CONTAINER_FILE_PATH"

# Start the container
timeout $3 docker start -a "${CONTAINER_ID}"

# Optionally, remove the container after execution
docker rm "${CONTAINER_ID}"
