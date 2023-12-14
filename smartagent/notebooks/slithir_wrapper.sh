#!/bin/bash
# usage: ./slithir_wrapper.sh <path_to_contract> <what_to_print> <solc_path>
# example: ./slithir_wrapper.sh /path/to/contract.sol slithir-ssa /path/to/solc
slither $1 --print $2 --solc $3