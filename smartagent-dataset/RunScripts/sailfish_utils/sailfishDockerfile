# Use the existing image as the base
FROM holmessherlock/sailfish:latest

# Install solc-select
RUN pip install solc-select
WORKDIR /root/sailfish/code/static_analysis/analysis
# Copy the custom entrypoint script into the container
COPY process_file.sh process_file.sh

# Make sure the script is executable
RUN chmod +x process_file.sh

# Set the new entrypoint
ENTRYPOINT ["/root/sailfish/code/static_analysis/analysis/process_file.sh"]
