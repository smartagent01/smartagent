# compile files
# solc --bin-runtime --abi 0x00000000441378008ea67f4284a57932b1c000a5.sol -o ./
import json
import subprocess
import os
def compile_file(file_path = '../AccessControl/CVE/all_files.json'):
    # file_path = '../AccessControl/SmartBugsWild/all_files.json'
    parent_dir = os.path.dirname(os.path.abspath(file_path))

    with open(file_path, 'r') as f:
        all_files = json.load(f)
    print (len(all_files))
    # Iterate over each item in the JSON
    for key, value in all_files.items():
        # Extract the version and file path
        version = value['version']
        file_path = value['file']
        real_file_path = os.path.join(os.path.abspath(parent_dir), file_path)
        # Construct the commands
        command = f"/users/user/.solcx/solc-v{version} --bin-runtime --abi {real_file_path} --overwrite -o {real_file_path.rsplit('/', 1)[0]}"
        print (command)
        # Execute the commands
        try:
            subprocess.run(command, shell=True, check=True)
            print(f"Commands executed for {file_path}")
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while executing commands for {file_path}: {e}")
        # break
import sys
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print ("Usage: python compile_contracts.py <json_file_path>")
        exit(1)
    file_path = sys.argv[1]
    compile_file(file_path)