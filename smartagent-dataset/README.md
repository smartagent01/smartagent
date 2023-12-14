# Smart-Agent Dataset

## Prerequisite

- docker
- [smartbugs](https://github.com/smartbugs/smartbugs), required to run Mythril

## Set up the test environment

### AChecker

Build image with

``` bash
cd docker/AChecker/ ; docker build -t achecker .
```

Test the built image,


``` bash
docker run --rm

```

### Sailfish


``` bash
cd docker/sailfish/ ; docker build -t sailfish-new .
```

### SpCon

``` bash
cd docker/SpCon/ ; docker build -t spcon-ethereum .
```


### Slither

``` bash
cd docker/slither/ ; docker build -t slither-smartagent .
```



## Test inputs and outputs



### CVE access control dataset

- `AccessControl/CVE/all_files.json` contains the meta information for
  each contract, including the path to each contract and the compiler version used
  to compile the contract and the main contract name containing the vulnerability.

```json
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
...
}
```

- `AccessControl/CVE/cve_bug_info.json` contains the bug information for each
  contract, including the function name containing the bug, the line number of the
  bug, and the CVE ID, etc.

```json
[
  {
    "cve": "CVE-2018-10666",
    "blockchain": "ETH",
    "address": "0xcc13fc627effd6e35d2d2706ea3c4d7396c610ea",
    "contract": "Owned",
    "function": "setOwner",
    "line_start": 33,
    "line_end": 36,
    "reference": [
      "https://medium.com/@jonghyk.song/aurora-idex-membership-idxm-erc20-token-allows-attackers-to-acquire-contract-ownership-1ff426cee7c6"
    ],
    "note": ""
  },
...
]
```

- `AccessControl/CVE/repair_output/{address}/{contract_file_name}/output_gpt-3.5-turbo-1106_final.sol`:
  this is the path to the repaired contracts generated by GPT3.5.
- `AccessControl/CVE/repair_output/{address}/{contract_file_name}/output_gpt-4-1106-preview_final.sol`:
  this is the path to the repaired contracts generated by GPT4.


### Access control bugs from the real hacks from 2021 to 2023
- `Real-Hacks-SunWeb3Sec/access-control/all_files.json` contains the meta
  information for each contract, including the path to each contract and the
  compiler version used to compile the contract and the main contract name
  containing the vulnerability.

```json
  "0xE85A08Cf316F695eBE7c13736C8Cc38a7Cc3e944": {
    "contract": [
      "FlippazOne"
    ],
    "file": "FlippazOne/0xE85A08Cf316F695eBE7c13736C8Cc38a7Cc3e944/0xE85A08Cf316F695eBE7c13736C8Cc38a7Cc3e944.sol",
    "version": "0.8.15",
    "blockchain": "Ethereum",
    "address": "0xE85A08Cf316F695eBE7c13736C8Cc38a7Cc3e944"
  },
...
}
```

- `Real-Hacks-SunWeb3Sec/access-control/{project_name}/bug_info.json`: contains the
  bug information manually labeled using data from https://github.com/SunWeb3Sec/DeFiHackLabs
- `Real-Hacks-SunWeb3Sec/access-control/repair_output/{project_name}/{contract_fiale_name}/output_gpt-3.5-turbo-1106_final.sol` :
  this is the path to the repaired contracts generated by GPT3.5.
- `Real-Hacks-SunWeb3Sec/access-control/repair_output/{project_name}/{contract_fiale_name}/output_gpt-4-1106-preview_final.sol` :
  this is the path to the repaired contracts generated by GPT4.


### Repair outputs from GPT3.5 and GPT4

The file `repair_summary.json` contains the diff information for the repaired
contracts generated by GPT3.5 and GPT4, for each repaired contract a `is_correct`
field is added to indicate whether the repair is valid or not.

``` json
[
  {
    "diff": [
      "--- original",
      "+++ repair",
      "@@ -445,9 +445,9 @@",
      "     event NewRC(address contr);",
      " ",
      "     function addMeByRC() public {",
      "-        require(tx.origin == owner);",
      "-",
      "-        rc[ msg.sender ]  = true;",
      "+        require(msg.sender == owner);",
      "+",
      "+        rc[msg.sender] = true;",
      " ",
      "         emit NewRC(msg.sender);",
      "     }"
    ],
    "original": "./AccessControl/CVE/0x403E518F21F5Ce308085Dcf6637758C61f92446A/RC.sol",
    "repaired": "./AccessControl/CVE/repair_output/0x403E518F21F5Ce308085Dcf6637758C61f92446A/RC.sol/output_gpt-3.5-turbo-1106_final.sol",
    "is_correct": "yes"
  },
  ...
]
```