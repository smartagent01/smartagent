import os
import json

import subprocess
import multiprocessing
from multiprocessing import Pool
import time
import random


experiment_script_path = os.path.abspath('./run_experiment.sh')
# default_timeout = 600
# tool=$1
# file=$2
# timeout=$3
# num_processes=$4
# output_folder=$5
# solc_version=$6
# to_date=$7 (optional, for spcon)
def compile_contract(files_json):
    ... # compile contract in json format
def search_for_bin(abs_file_path, json_data):
    path_parts = abs_file_path.split("/")
    path_parts[-1] = json_data.get("contract")[0] +  ".bin-runtime"
    return "/".join(path_parts)

def get_commands_to_run_tool(json_data, script_path, base_output_path, timeout=60, tools = "all"):
    commands = []
    abs_file_path = os.path.join(base_path, json_data.get("file"))
    binary_file_path = search_for_bin(abs_file_path, json_data)
    if "mythril" in tools or tools == "all":
        commands.append(f'{script_path} mythril {abs_file_path} {timeout} 1 {base_output_path}/mythril {json_data.get("version")}')
    if "slither" in tools or tools == "all":
        commands.append(f'{script_path} slither {abs_file_path} {timeout} 1 {base_output_path}/slither {json_data.get("version")}')
    if "semgrep" in tools or tools == "all":
        commands.append(f'{script_path} semgrep {abs_file_path} {timeout} 1 {base_output_path}/semgrep {json_data.get("version")}')
    if "spcon" in tools or tools == "all":
        if json_data.get("blockchain") in ["ETH", "Ethereum"]:
            commands.append(f'{script_path} spcon {json_data.get("address")} {timeout} 1 {base_output_path}/ {json_data.get("version")}')
    if "achecker" in tools or tools == "all":
        if os.path.exists(binary_file_path):
            commands.append(f'{script_path} achecker {binary_file_path} {timeout} 1 {base_output_path}/ {json_data.get("version")}')
        else:
            print ("\n\nAchecker bin not found, skip\n\n")
    if "sailfish" in tools or tools == "all":
        commands.append(f'{script_path} sailfish {abs_file_path} {timeout} 1 {base_output_path}/ {json_data.get("version")}')
    return commands
# Running the bash script with arguments
# subprocess.run(command, shell=True)
def run_command(command):
    try:
        # Execute the command and wait for it to complete
        # random sleep to avoid API rate limit for some tools
        delay = random.uniform(0, 10)
        print ("sleep for ", delay)
        time.sleep(delay)
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return command, result.stdout.decode(), result.stderr.decode()
    except subprocess.CalledProcessError as e:
        # Return standard error output if the command fails
        print ("error ", e)
        return command, e.stdout.decode(), e.stderr.decode()

def execute_commands(commands):
    try:
        # Create a pool of worker processes
        with Pool(processes=min(len(commands), multiprocessing.cpu_count())) as pool:
            # Execute the commands in parallel and wait for all to complete
            results = pool.map(run_command, commands)
            print("All commands have been executed.")
            return results
    except Exception as e:
        print(f"An error occurred during command execution: {e}")

def run_experiment(files_json, base_path, tools='all', num_contracts=0, timeout=600, jobs=6):
    if type(tools) == str and tools != "all":
        tools = tools.split(",")
    count = 0
    all_commands = []
    for key_,val_ in files_json.items():
        # print (key_,val_)
        file_path = os.path.join(base_path, val_.get("file"))

        print ("process ", file_path)
        output_path = os.path.join(base_path, f'tool_output/{val_.get("file")}')
        # print (output_path)
        folder_path = os.path.dirname(file_path)
        found_bin = False
        for file in os.listdir(folder_path):
            if file.endswith('.bin-runtime'):
                found_bin = True
                break
        # if not found_bin:
        #     print ("bin not found")
            # raise Exception("Need to compile contract first for some tools")
            # compile_contract(files_json)
        print ("start running experiment")
        commands = get_commands_to_run_tool(val_, experiment_script_path, output_path, timeout=timeout, tools = tools)
        all_commands.extend(commands)

        # for command in commands:
        #     print (command)
        # res = execute_commands(commands)
        if num_contracts > 0:
            count += 1
            if count >= num_contracts:
                break
    # Split the commands into chunks based on the number of jobs
    # print ("all_commands ", all_commands)
    # for command in all_commands:
    #     print (command)
    for i in range(0, len(all_commands), jobs):
        chunk_commands = all_commands[i:i+jobs]
        print ("chunk_commands ", chunk_commands)
        execute_commands(chunk_commands)

    print ("end running experiment")

# run_experiment(files)

import argparse
if __name__ == '__main__':
    # -f json file, -t tool, -n number of contract to test (will stop after n contracts), default all
    # -j number of processes, default 1
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file",type=str, default='../AccessControl/CVE/all_files.json', help="json file")
    parser.add_argument("-t", "--tool", type=str, default="all", help="tool name")
    parser.add_argument('--timeout', type=int, default=600, help='timeout for each tool')
    parser.add_argument("-n", "--number",type=int, default=0, help="number of contracts to test")
    parser.add_argument("-s", "--script",type=str, default='./run_experiment.sh', help="script path")
    parser.add_argument("-j", "--jobs",type=int, default=6, help="number of processes")

    args = parser.parse_args()
    files_config = os.path.abspath(args.file)
    jobs = args.jobs
    experiment_script_path = os.path.abspath(args.script)
    base_path = '/'.join(files_config.split("/")[0:-1])
    timeout = args.timeout
    print ("base_path ",base_path)
    with open(files_config) as f:
        files = json.load(f)
    run_experiment(files, base_path, args.tool, args.number, timeout, jobs)

# files_config = os.path.abspath('../AccessControl/CVE/all_files.json')
# base_path = files_config.split("/")[0:-1]

# with open(files_config) as f:
#     files = json.load(f)
# print (files)
#