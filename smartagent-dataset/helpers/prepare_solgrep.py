
import os
import json
import subprocess

def run_solgrep(file_path):
    print ("get data", file_path)
    file_name = file_path.split('/')[-1]
    command = ['./solgrep_wrapper.sh', file_path, "\"modifier.name\"", file_path.replace(file_name, f"solgrep_modifier_data.json")]
    result = subprocess.run(command,check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    command = ['./solgrep_wrapper.sh', file_path, "\"function.name\"", file_path.replace(file_name, f"solgrep_function_data.json")]
    result = subprocess.run(command,check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def prepare_solgrep_data(metadata_path):
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    base_path  = os.path.dirname(os.path.abspath(metadata_path))
    print (len(metadata))
    for meta_k,meta_val in metadata.items():
        file_path = os.path.join(base_path,meta_val.get("file"))
        run_solgrep(file_path)
        # break
import sys
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print ("Usage: python prepare_solgrep.py <metadata_path>")
        exit(1)
    json_path = sys.argv[1]
    prepare_solgrep_data(json_path)