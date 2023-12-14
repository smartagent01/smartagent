
if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <file-path> <solc-version> <timeout> <output-file>"
    exit 1
fi

# Convert the relative file path to an absolute path
FILE_PATH=$(realpath "$1")
OUTPUT_FILE=$(realpath "$4")
# Define the path inside the container where the file will be copied
CONTAINER_FILE_PATH="/home/ethsec/$(basename "$FILE_PATH")"

# Create a new Docker container without starting it
CONTAINER_ID=$(docker create slither-smartagent "$CONTAINER_FILE_PATH" "$2")

# Copy the file into the container at the specified path
docker cp "$FILE_PATH" "${CONTAINER_ID}:${CONTAINER_FILE_PATH}"
echo "File copied : $CONTAINER_FILE_PATH"

# Start the container
docker start -a "${CONTAINER_ID}"
# Optionally, remove the container after execution
docker cp "${CONTAINER_ID}:/home/ethsec/output.json" "$OUTPUT_FILE"

docker rm "${CONTAINER_ID}"


# slither StaxLPStaking.sol  --json output.json --json-types detectors --exclude-optimization --exclude-dependencies --exclude-informational