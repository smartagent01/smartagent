#!/bin/bash
# before running this, make sure set up dockers of smartbugs, achecker, spcon, and sailfish
# export PATH=$PATH:this_folder
# usage : ./run_experiment.sh {tool} {file} {timeout} {output_folder} {other_args}
# example : ./run_experiment.sh tool test.bin-runtime 0.1.2 600 2021-01-01 output

# Check if at least 4 arguments are provided
if [ "$#" -lt 5 ]; then
    echo "Usage: $0 tool file timeout num_processes output_folder solc_version [other_args]"
    exit 1
fi

# Assign arguments to variables
tool=$1
file=$2
timeout=$3
num_processes=$4
output_folder=$5
solc_version=$6

# Check if the file exists
# if [ ! -f "$file" ]; then
#     echo "Error: File '$file' not found."
#     exit 1
# fi

# Check if timeout is a number
if ! [[ $timeout =~ ^[0-9]+$ ]]; then
    echo "Error: Timeout must be a number."
    exit 1
fi

# Check if output_folder exists, create if it doesn't
if [ ! -d "$output_folder" ]; then
    echo "Output folder '$output_folder' not found. Creating it."
    mkdir -p "$output_folder"
fi
script_dir=$(dirname "$(realpath "$0")")
echo "script_dir: $script_dir"
# Handle other arguments
other_args=("${@:7}")  # Assigns all arguments starting from the 7th to other_args
if [ $# -eq 6 ]; then
    to_date="2022-05-23"
else
    to_date=$7
fi

# Check if tool is in the list of allowed tools
case $tool in
    mythril)
        # Command for mythril
        echo "Running Mythril..."
        # Your command here
        smartbugs -t mythril -f $file --results $output_folder --json --overwrite --timeout $timeout --processes $num_processes
        ;;
    slither)
        # Command for slither
        echo "Running Slither..."
        # Your command here
        "$script_dir/slither.sh" $file $solc_version $timeout $output_folder/slither_raw.json
        # smartbugs -t slither -f $file --results $output_folder --json --overwrite --timeout $timeout --processes $num_processes
        ;;
    semgrep)
        # Command for semgrep
        echo "Running Semgrep..."
        # Your command here
        smartbugs -t semgrep -f $file --results $output_folder --json --overwrite --timeout $timeout --processes $num_processes
        ;;
    achecker)
        # Command for achecker
        echo "Running AChecker... $file $solc_version $timeout"
        # Your command here
        #
        "$script_dir/achecker.sh" $file $solc_version $timeout > $output_folder/achecker_output.txt 2>&1
        ;;
    spcon)
        # Command for spcon
        echo "Running SPCON... $file $timeout $to_date"
        # Your command here
        "$script_dir/spcon_eth.sh" $file $timeout $to_date > $output_folder/spcon_output.txt 2>&1
        ;;
    sailfish)
        # Command for sailfish
        echo "Running Sailfish... $file $solc_version $timeout"
        # Your command here
        "$script_dir/sailfish.sh" $file $solc_version $timeout > $output_folder/sailfish_output.txt 2>&1
        ;;
    *)
        echo "Error: Invalid tool. Tool must be one of [mythril, slither, semgrep, achecker, spcon, sailfish]."
        exit 1
        ;;
esac

# Echo the arguments for confirmation or debugging
echo "Tool: $tool"
echo "File: $file"
echo "Timeout: $timeout seconds"
echo "Output Folder: $output_folder"
if [ ${#other_args[@]} -gt 0 ]; then
    echo "Other Arguments: ${other_args[*]}"
fi

# Your script's main logic goes here
# ...


