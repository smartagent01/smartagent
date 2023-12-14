
### SmartAgent
#### Requirements
* Tested on Python 3.9 Ubuntu 20.04
* solgrep : `npm install -g solgrep`
* pip packages : `pip install -r requirements.txt`
* OpenAI API with gpt-4 access. Set the key in enviroment before running SmartAgent: `export OPENAI_API_KEY= <Your OpenAI API key>`


#### Run :
0. Prepare steps: (the steps are already done for the examples in this repository. You only need to run them if you try on a new dataset):
    * Prepare json config file following the format in `samples/access_control/file_config.json`
    * Run solgrep on all contract `cd smartagent-dataset/helpers/ ; python prepare_solgrep.py [json config file]`
    * Compile all the contracts: `cd smartagent-dataset/helpers/ ; python prepare_solgrep.py [json config file]` (Note: the solc compilers path is different on your system)
    * Prepare vector database. Please take a look at `notebooks/test_vector_db.ipynb`. The database is already prepared on `src/.chromadb`
    * Prepare other tools' docker following `smartagent-dataset/README.md`

1. Run detector agent
    `python smart_agent.py -a detector -f ../samples/access_control/file_config.json`
2. Run other tools
    * `cd ../smartagent-dataset/RunScripts`
    * `python run.py -h`
    * For example run with `python run.py -f ../AccessControl/CVE/all_files.json -j 10`


3. Run aggregator step 1
    * Work dir : cd  `./smartagent/src`
    * Parse the tools output first `python parse_result_to_files.py ../samples/access_control/file_config.json`
    * The above step will generate one json files for each tool in the `parsed_tool_output` folder in the same folder with the json config file.
    * Merge the tools output files `python smart_agent.py -a aggregator -f ../samples/access_control/file_config.json`
    * The above step will merge all tools json files into to a file with model name e.g. .`output_gpt-3.5-turbo-1106.json`. To merge results of GPT-4 detector, use -m flag when running smart-agent `-m gpt-4-1106-preview`

4. Run aggregator step 2
    * Work dir : cd `./smartagent/src`
    * Run the aggregator for False positive detection ``:
    `python smart_agent.py -a aggregator -f ../samples/access_control/parsed_tool_output/output_gpt-3.5-turbo-1106.json -c ../samples/access_control/file_config.json -m gpt-4-1106-preview_filtered`
    * The aggregated results can be found in `parsed_tool_output` with name suffix `..gpt-4-1106-preview_filtered.json`


5. Run repair
    * Work dir : cd `./smartagent/src`
    * Run functional-level repair using the repair config.json
    * `python smart_agent.py -a repair -f ../samples/access_control/repair_config.json -m gpt-4-1106-preview_filtered`

