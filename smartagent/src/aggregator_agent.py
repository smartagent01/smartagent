"""
repair-agent.py repair bugs of smart contracts. currently supports access control bugs
"""
from collections import defaultdict
from dataclasses import dataclass
import os
import subprocess
import sys
import json
import argparse
import time
import multiprocessing
from multiprocessing import Pool
from langchain.llms import OpenAI
from langchain.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.schema import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.cache import SQLiteCache
from langchain.globals import set_llm_cache

from langchain.document_loaders import TextLoader
from langchain.text_splitter import CharacterTextSplitter
from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings



import solcx
# from utils.utils import get_num_token_from_string
from utils.utils import run_command, get_num_token_from_string
from utils.tool_parsers import parse_all_tools

# from utils.preprocessing import smartbugs_preprocess
# models : [gpt-4-1106-preview, gpt-3.5-turbo-1106]
# https://python.langchain.com/docs/modules/chains/foundational/sequential_chains

# the prompt is about 128 tokens
code_length_limit = {
    "gpt-4-1106-preview": 128000,
    "gpt-3.5-turbo-1106": 16000,
    "llama": 4000,
}
@dataclass
class BugInfo:
    function_name : str
    tool_name : str
    contract_name : str
    main_contract_name : str
    solc_version : str
    file_path : str
    output_path : str
    start_line: int = 0
    end_line: int = 0

RESULT_SUFFIX = ""

def build_tools_description(tools):
    tool_description = ""
    prompt_data = json.load(open("prompt_data/tool_knowledge.json"))
    for tool in tools:
        if "gpt" in tool:
            tool_description_data = prompt_data.get("llm")
        else:
            tool_description_data = prompt_data.get(tool)
        if (tool_description_data is None):
            continue
        tool_description += "\n".join(tool_description_data)

    return tool_description


    # # uncomment to get intermediate results
def false_positive_detection(buggy_code, contract_code, tools=None, model_name= "gpt-3.5-turbo-1106", log_file="log.txt" ):
    if get_num_token_from_string(contract_code) > code_length_limit.get(model_name):
        contract_code = "\nThe contract code is too long, reply with your best guess.\n"
        # return False
    embeddings_model = OpenAIEmbeddings()
    vector_store = Chroma(persist_directory=".chroma_db", embedding_function=embeddings_model)
    docs = vector_store.similarity_search(buggy_code, k=1)
    rag_sample = docs[0].page_content
    print("found_simlar function " , rag_sample)
    prompt_data = json.load(open("prompt_data/prompt_template.json"))
    llm_detector_prompts = prompt_data.get('llm-detector')
    # llm_analyzer_prompts = prompt_data.get('llm-output-analyzer')
    bug_type = "access control"
    tool_description = build_tools_description(tools)
    bug_description = llm_detector_prompts.get('bug-description')
    bug_samples = llm_detector_prompts.get('bug-sample')
    if type(bug_samples) == list:
        bug_samples = "\n ".join(bug_samples)
    print ("bug samples ", bug_samples)
    print ("bug description ", bug_description)

    detector_prompt = PromptTemplate.from_template(
        "You are an expert vulnerability analyzer specialized in filtering false positve bug report on access control and permission related bugs for smart contracts.\n"
        "You are given a bug report from tools that detects access control bugs in smart contracts.\n"
        "The tool(s) description: \n"
        "{tool_description}\n"
        "\n"
        "The bug description is: \n"
        "{bug_description}\n"
        "\n"
        "Some common (but nonexhaustive) bug patterns are: \n"
        "{bug_samples}\n"
        "\n"
        "Some common (but nonexhaustive) false positive patterns are: \n"
        "  Internal function \n"
        "  Function with intended logic\n"
        "\n"
        "To assist you, there is a false alarm that can be used as reference: \n"
        "{rag_sample}"
        "\n"

        "The source code of the contract in context is enclosed in the following code block:\n"
        "```\n"
        "{contract_code}"
        "\n```\n"
        "\n"
        "The function source code in the following code block is reported by the tool(s) to have an access control bug:\n"
        "```\n"
        "{buggy_function}"
        "\n```\n"

        "Using the above description and your own knowledge, detect if the function having access control bug below is false positive.\n"
        # "Answer YES if the bug is a false positive or NO if it is a real access control bug.\n"
        # "If you are not sure, reply NO. \n"
        "If you are not sure, do not mark it as false alarms. Answer YES if the bug is a false positive or NO if it is a real access control bug.\n"
        "Only reply with YES or NO. Do not reply with any other text.\n"
        )

    detector_prompt = detector_prompt.partial(tool_description=tool_description,
                                                rag_sample= rag_sample,
                                                bug_description=bug_description,
                                                bug_samples=bug_samples,
                                               contract_code=contract_code,)

    # print ("detector prompt ", detector_prompt.format(buggy_function = buggy_code))
    llm = ChatOpenAI(model_name=model_name, temperature=0)
    detector_chain = detector_prompt | llm | StrOutputParser()
    # # all_result = buggy_code
    all_result = detector_chain.invoke({"buggy_function": buggy_code})
    with open(log_file, "a") as f:
        f.write(buggy_code)
        f.write("\n------\n")
        f.write(rag_sample)
        f.write("\n------\n")
        f.write(all_result)
        f.write("\n=========\n")


    if "yes" in all_result.lower()[:20]:
        print ("false positive detected")
        return True # false positive
    else:
        return False


def analyze_step_by_step(contract_code, model_name= "gpt-3.5-turbo-1106", log_file="log.txt" ):
    ...
    return "length of contract code is too long"
def analyze_step_by_step_with_specific_bug_type(contract_code, model_name= "gpt-3.5-turbo-1106", log_file="log.txt", bug_type="access-control" ):
    ...
    return "length of contract code is too long"

def get_function_text(function_data, contract_code, function_name, contract_name):
    if function_name == None or contract_name == None:
        raise Exception("function name or contract name is not provided")
    function_text = ""
    function_data = list(function_data.values())[0]
    max_distance = 0
    max_distance_loc = [-1, -1]
    matched_loc = [-1, -1]
    # print ("get function text ", function_name, function_data)
    match_str = f"{contract_name}.{function_name}"
    match_at_least_one = False
    for function in function_data:
        # print ("function ", function.get("tag"))
        # print ("match str ", match_str)
        if function.get("info") == function_name:
            match_at_least_one = True
            print ("found function ", function)
            if function.get("loc")[2] - function.get("loc")[0] > max_distance:
                # print ("found function ", function)
                max_distance_loc = [function.get("loc")[0], function.get("loc")[2]]
                max_distance = function.get("loc")[2] - function.get("loc")[0]
        if match_str in function.get("tag"):
            print ("found function ", function)
            matched_loc = [function.get("loc")[0], function.get("loc")[2]]
    if not match_at_least_one:
        return "", [-1, -1]
    lines = contract_code.split("\n")
    # print (lines)
    # print ("matched loc ", matched_loc)
    # print ("max distance loc ", max_distance_loc)
    if matched_loc[0] != -1:
        function_text =  "\n".join(lines[matched_loc[0]-1:matched_loc[1]])
        return function_text, matched_loc
    else:
        function_text =  "\n".join(lines[max_distance_loc[0]-1:max_distance_loc[1]])
        return function_text, max_distance_loc

def get_repair_function(tool_name):
    ...


def process_file_wrapper(args):
    # Unpack the arguments
    file_path, bug_info,  model_name, output_file, log_file, bug_type = args
    repair_one_file(file_path, bug_info, model_name, output_file, log_file, bug_type)

parsed_tool_output = {
    "slither" : "slither_addresses.json",
    "semgrep" : "semgrep_addresses.json",
    "mythril" : "mythril_addresses.json",
    "spcon" : "spcon_addresses.json",
    "achecker" : "achecker_addresses.json",
    "gpt3" : "gpt3_addresses.json",
    "gpt4"  : "gpt4_addresses.json",
}
def read_json(file_path):
    if not os.path.exists(file_path):
        return {}
    with open(file_path, 'r') as file:
        return json.load(file)
def merge_dicts(file_list, tool_list, output_file="merged.json"):
    print ("file list ", file_list)
    dict_list = [read_json(path) for path in file_list]
    merged_dict = defaultdict(list)
    for idx,d in enumerate(dict_list):
        for key, value_list in d.items():
            existing_locations = set(item['location'] for item in merged_dict[key])
            print (value_list)
            if type (value_list) == dict:
                # print ("item ", item)
                if value_list['location'] not in existing_locations:
                    value_list['tool'] = [tool_list[idx]]
                    merged_dict[key].append(value_list)
                    existing_locations.add(value_list['location'])
                else:
                    for item in  merged_dict[key]:
                        if item['location'] == value_list['location']:
                            item['tool']+= tool_list[idx]
            else:
                for item in value_list:
                    print ("item ", item)
                    if item['location'] not in existing_locations:
                        item['tool'] = [tool_list[idx]]
                        merged_dict[key].append(item)
                        existing_locations.add(item['location'])
                    else:
                        for item in  merged_dict[key]:
                            if item['location'] == item['location']:
                                item['tool'] += [tool_list[idx]]
    merged = dict(merged_dict)
    if not os.path.exists(output_file):
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as file:
        json.dump(merged, file, indent=2)


def process_aggregated_file(contract_config_path,bug_config_path, model_name= "gpt-3.5-turbo-1106", log_file="log.txt"):
    result_file_path = bug_config_path.replace(".json", f"_{model_name}_filtered.json")
    with open (bug_config_path, "r") as f:
        bug_data = json.load(f)
    all_files = json.load(open(contract_config_path))
    base_directory = os.path.dirname(contract_config_path)
    count_sample = 0
    seen_bugs = {}
    for key, value in bug_data.items():
        print ("key ", key)
        print ("value ", value)
        del_bug = []
        for bug in value:
            print ("function ", bug.get("location"))
            tools = list(set(bug.get("tool")))
            if len(tools) >= 3: # at least 3 tools agree
                print ("tools ", tools)
                continue
            print ("tool ", )
            print (bug)
            unique_key = f"{key},{bug.get('location')}"
            if unique_key in seen_bugs:
                continue
            seen_bugs[unique_key] = 1
            print ("unique key ", unique_key)
            # code_file = all_files.get(key).get("file")
            # file_path = os.path.join(base_directory)
            if key not in all_files:
                del_bug.append(bug)
                continue
            code_file = all_files.get(key).get("file")
            real_code_file = os.path.join(base_directory, code_file)
            file_path = os.path.dirname(real_code_file)
            contract_code = open(real_code_file, "r").read()
            function_name = bug.get("location")
            contract_name = all_files.get(key).get("contract")[0]
            # print ("contract name ", contract_name)
            solgrep_function_file = os.path.join(file_path, "solgrep_function_data.json")
            # print (solgrep_function_file)
            if os.path.exists(solgrep_function_file):
                function_data = json.load(open(solgrep_function_file))
            # print ("function data ", function_data)
            function_text, function_loc = get_function_text(function_data, contract_code, function_name, contract_name)
            # false_positive_detection()
            # print ("function text ", function_text, function_loc)
            count_sample += 1
            if function_text == "":
                del_bug.append(bug)
                continue
        #     # print ("contract code ", contract_code)
            false_positive = false_positive_detection(function_text, contract_code, tools=tools, model_name=model_name, log_file=log_file)
            if false_positive:
                del_bug.append(bug)
        for bug in del_bug:
            value.remove(bug)
    print ("count sample ", count_sample)
    with open(result_file_path, "w") as f:
        json.dump(bug_data, f, indent=2)
    # with open(result_file_path, "w") as f:
    #     f.write(json.dumps(bug_data))

def process_config_file(config_file, result_dir, model_name= "gpt-3.5-turbo-1106", jobs=1\
                        , bug_type="access-control", output_file="aggregated_result.json"\
                            , log_file="aggregator_log.txt"):
    base_path = os.path.dirname(config_file)
    print ("base_path ",base_path)
    with open(config_file) as f:
        files = json.load(f)
    tasks = []
    task_count = 0
    #aggregate first
    result_dir = os.path.join(base_path, result_dir)
    result_file = os.path.join(base_path,"parsed_tool_output/" + output_file)

    result_file = result_file.replace(".json", f"_{model_name}{RESULT_SUFFIX}.json")
    if model_name == "gpt-3.5-turbo-1106":
        tools = ["slither", "mythril", "spcon", "achecker","gpt3"]
        tool_file_names = [f"{tool}_addresses.json" for tool in tools]
        tool_file_paths = [os.path.join(result_dir, f"{tool}_addresses.json") for tool in tools]
        merge_dicts(tool_file_paths, tool_list=tools, output_file=result_file)
        # res = parse_all_tools(config_file, result_dir, tools=tools)
    else:
        tools = ["slither", "mythril", "spcon", "achecker","gpt4"]
        tool_file_names = [f"{tool}_addresses.json" for tool in tools]
        tool_file_paths = [os.path.join(result_dir, f"{tool}_addresses.json") for tool in tools]
        merge_dicts(tool_file_paths, tool_list=tools, output_file=result_file)
        # res = parse_all_tools(config_file, result_dir)
    # print (res)
    print ("result file ", result_file)
    # with open(result_file, "w") as f:
        # f.write(json.dumps(res))
    return

if __name__ == "__main__":
    # set_llm_cache(SQLiteCache(database_path=".langchain.db"))
    # get argument from command line
    # python <file>.py <config_file> -r <result_dir> -m <model_name> -o <output_file> -l <log_file> -j <number of processes>
    # use argparse to parse arguments
    parser = argparse.ArgumentParser(description='Process some arguments.')

    # File name as either a positional argument or with a flag
    parser.add_argument('-f', '--file', dest='file_name', type=str,
                        help='Name of the file to process')
    parser.add_argument('positional_file_name', nargs='?', type=str,
                        help='Name of the file to process (positional argument)')
    parser.add_argument('-c', '--config', dest='config_file', default="NA", type=str,)
    parser.add_argument('-r', '--result', dest='result_dir', help=' result from the parent dir of config file', type=str, required=False, default="parsed_tool_output")
    # Model name must be specified with a flag
    parser.add_argument('-m', '--model', dest='model_name', type=str, required=False, default="gpt-3.5-turbo-1106",
                        help='Name of the model to use')

    parser.add_argument('-o', '--output', dest='output_file', type=str, required=False, default="aggregated_result.json")
    parser.add_argument('-l', '--log', dest='log_file', type=str, required=False, default="aggregator_log.txt")
    parser.add_argument('-j', '--jobs', dest='jobs', type=int, required=False, default=1)
    parser.add_argument('--suffix', dest='suffix', type=str, required=False, default="")
    args = parser.parse_args()
    RESULT_SUFFIX = args.suffix
    # Use the file name provided by either the flag or the positional argument
    file_name = args.file_name or args.positional_file_name
    log_file = args.log_file
    output_file = args.output_file
    result_dir = args.result_dir
    jobs = args.jobs
    contract_config_path=args.config_file
    #debugging
    if args.config_file != "NA":
        process_aggregated_file(contract_config_path, file_name, model_name=args.model_name, log_file=log_file)
        exit()
    if ".json" in file_name:
        process_config_file(file_name, result_dir=result_dir, model_name=args.model_name, jobs=jobs, \
                            output_file=output_file, log_file=log_file)

