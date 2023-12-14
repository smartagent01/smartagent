Sample running tools and file:
run 3 smartbugs tools
./run_experiment.sh slither ../AccessControl/CVE/0x5ABC07D28DCC3B60a164d57e4E3981a090c5d6De/BOMBBA.sol 60 1 test_slither
./run_experiment.sh mythril "../../test_contracts/N00d.sol" 60 1 test_myth
./run_experiment.sh semgrep ../../test_contracts/N00d.sol 60 1 test_semgrep

# Achecker run with binary ok, source code mode is having problem. We can just compile first and run
./RunScripts/run_experiment.sh achecker AccessControl/CVE/0x2Ef27BF41236bD859a95209e17a43Fbd26851f92/MorphToken.bin-runtime 60 1 test_output/ 0.4.23

# spcon run with onchain address (currently only ethereum supported)
./RunScripts/run_experiment.sh spcon 0xcc13fc627effd6e35d2d2706ea3c4d7396c610ea 60 1 test_output/ 0.1.2


./RunScripts/run_experiment.sh sailfish ../test_contracts/reentrance.sol 60 1 test_output/ 0.4.23

# Run with json config
config sample in AccessControl/CVE:
{
  "0x2Ef27BF41236bD859a95209e17a43Fbd26851f92/MorphToken.sol": {
    "file": "0x2Ef27BF41236bD859a95209e17a43Fbd26851f92/MorphToken.sol",
    "contract": [
      "MorphToken"
    ],
    "version": "0.4.26",
    "blockchain": "ETH",
    "address": "0x2Ef27BF41236bD859a95209e17a43Fbd26851f92"
  },
  ....
}

python run.py -h