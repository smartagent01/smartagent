#!/bin/bash
# usage: ./solgrep_wrapper.sh <path_to_contract> <filter_expression> <output_file>
solgrep $1 --find=$2 -o $3