# Use the existing image as the base
FROM trailofbits/eth-security-toolbox

WORKDIR /home/ethsec/
# Copy the custom entrypoint script into the container
COPY process_file.sh process_file.sh

# Make sure the script is executable
# RUN chmod +x process_file.sh

# Set the new entrypoint
ENTRYPOINT ["/home/ethsec/process_file.sh"]
