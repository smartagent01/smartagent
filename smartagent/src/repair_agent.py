"""
repair-agent.py repair bugs of smart contracts. currently supports access control bugs
"""
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
import solcx

# from utils.utils import get_num_token_from_string

from utils.utils import (
    achecker_parser,
    parse_gpt_result,
    parse_slither_result,
    run_command,
    get_num_token_from_string,
)

import detector_agent
from detector_agent import analyze_full_file

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
    function_name: str
    tool_name: str
    contract_name: str
    main_contract_name: str
    solc_version: str
    file_path: str
    output_path: str
    start_line: int = 0
    end_line: int = 0


@dataclass
class CompilationResult:
    success: bool
    error_message: str
    contract_bin: str = ""


RESULT_SUFFIX = ""
MAX_ITERATION = 3


def remove_code_block(code):
    lines = code.split("\n")
    filtered_lines = [line for line in lines if not line.startswith("```")]
    return "\n".join(filtered_lines)


def replace_function(contract_code, patched_function, bug_info):
    lines = contract_code.split("\n")
    patched_lines = patched_function.split("\n")
    lines[bug_info.start_line - 1 : bug_info.end_line] = patched_lines
    return "\n".join(lines)


def process_repair_result(all_result, contract_code, bug_info, write_file):
    patched_function = remove_code_block(all_result)
    patched_code = replace_function(contract_code, patched_function, bug_info)
    with open(write_file, "w") as f:
        f.write(patched_code)
    return patched_code, write_file


def clean_error_string(error_string):
    lines = error_string.split("\n")
    cleaned_lines = []
    start_error = False
    for line in lines:
        if "solcx.exceptions.SolcError:" not in line:
            start_error = True
        if start_error:
            cleaned_lines.append(line)
    if len(cleaned_lines) == 0:
        return error_string
    return "\n".join(cleaned_lines)


def compile_contract(patched_code, bug_info):
    # patched_code = patched_code + "{ "
    if bug_info.solc_version == "0.4.10":
        return CompilationResult(True, "", "")
    try:
        output = solcx.compile_source(
            patched_code,
            output_values=["bin-runtime"],
            solc_version=bug_info.solc_version,
        )
    except Exception as e:
        error_string = str(e)
        print("error string ", error_string)
        error_string = clean_error_string(error_string)
        return CompilationResult(False, error_string, "")
    # print ("compiler output ", output)
    for key, val in output.items():
        contract_name = key.split(":")[1]
        if contract_name == bug_info.main_contract_name:
            if len(val.get("bin-runtime")) == 0:
                print("no runtime bytecode")
            else:
                contract_bin = val.get("bin-runtime")
    return CompilationResult(True, "", contract_bin)


tool_scripts = {
    "achecker": "../../smartagent-dataset/RunScripts/achecker.sh",
    "slither": "../../smartagent-dataset/RunScripts/slither.sh",
}


def validate_repair_result(
    patched_file, bug_info, compilation_result, model_name="gpt-3.5-turbo-1106"
):
    if not compilation_result.success:
        return False
    if bug_info.tool_name == "achecker":
        # write bin-runtime to file
        with open(patched_file + ".bin-runtime", "w") as f:
            f.write(compilation_result.contract_bin)
        # run achecker
        res = run_command(
            f"{tool_scripts.get('achecker')} {patched_file}.bin-runtime 0.1.2 600"
        )
        # print (res)

        validation_res = achecker_parser(res[1])
        with open(patched_file + ".out", "w") as f:
            f.write(res[1])
            f.write(str(validation_res))

        return validation_res[0]
        # print (bug_info.tool_name, "validation res ", validation_res)
    elif bug_info.tool_name == "slither":
        # "Usage: $0 <file-path> <solc-version> <timeout> <output-file>"
        res = run_command(
            f"{tool_scripts.get('slither')} {patched_file} {bug_info.solc_version} 600 {patched_file}_slither.json"
        )
        validation_res = parse_slither_result(f"{patched_file}_slither.json")
        print(bug_info.tool_name, "validation res ", validation_res)
        return validation_res[0]
    else:
        # use llm
        # analyze_full_file(contract_code, model_name= "gpt-3.5-turbo-1106", log_file="log.txt" ):
        contract_code = open(patched_file, "r").read()
        res = analyze_full_file(
            contract_code, model_name=model_name, log_file=patched_file + ".log"
        )
        with open(patched_file + ".out", "w") as f:
            f.write(res)
        validation_res = parse_gpt_result(res, bug_info.function_name)
        print(bug_info.tool_name, "validation res ", validation_res)
        return validation_res[0]
    return True


def prepare_followup_prompt(
    memory_prompts, memory_results, compilation_result, validation_result
):
    followup_template = PromptTemplate.from_template(
        "You are an expert in code repair, with a specialization in repairing access control and permission-related bugs in smart contracts. \n"
        "\n"
        "Use the following pieces of context to continue to fix the buggy function in the provided smart contract."
        "\n```"
        "{context_text}"
        "\n```\n"
        "{extra_context}\n"
        "The bug inspector also may have false positive, if you are confident that the bug is fixed, reply with `STOP`.\n"
        "If you want to continue to fix the bug, reply with the fixed function code and nothing else.\n"
        "\n"
    )
    context_text = ""
    for i in range(len(memory_results)):
        if i < len(memory_prompts):
            context_text += f"Query {i+1}: \n"
            context_text += memory_prompts[i]
            context_text += "\n"
        context_text += f"Repair Result Round {i+1}: \n"
        context_text += memory_results[i]
        context_text += "\n"
        context_text += (
            "Proceed to compile the patched contract: Success!\n"
            if compilation_result.success == True
            else "Process to compile the contract: Failed with error "
            + compilation_result.error_message
            + "\n"
        )
        context_text += (
            "Bug inspection for the patched code: Free of bug!\n"
            if validation_result == True
            else "Bug inspection for the patched code: the bug still exists\n"
        )
        context_text += "-" * 80
        context_text += "\n"

    followup_prompt = followup_template.partial(context_text=context_text)
    print("\n\nfollowup prompt ", followup_prompt)
    # print ("\n\n")
    return followup_prompt
    # # uncomment to get intermediate results


def repair_agent(
    buggy_code,
    contract_code,
    modifiers_text,
    bug_info,
    model_name="gpt-3.5-turbo-1106",
    log_file="log.txt",
):
    memory_prompts = []  # for multiple rounds of interaction
    memory_results = []
    prompt_data = json.load(
        open("prompt_data/prompt_template.json")
    )
    llm_detector_prompts = prompt_data.get("llm-detector")
    # llm_analyzer_prompts = prompt_data.get('llm-output-analyzer')
    bug_type = "access control"
    bug_description = llm_detector_prompts.get("bug-description")

    sample_contract = llm_detector_prompts.get("sample-contract")
    contract_name = bug_info.contract_name
    solc_version = bug_info.solc_version
    # print ("bug samples ", bug_samples)
    llm_repair_prompts = prompt_data.get("llm-repair")
    repair_instructions = llm_repair_prompts.get("repair-samples")
    if type(repair_instructions) == list:
        repair_instructions = "\n ".join(repair_instructions)
    # print ("modifiers_text ", modifiers_text)
    if len(modifiers_text) > 0:
        modifiers_text = (
            "There are existing modifiers in the source code that may be used if necessary, enclosed in the below code block:\n"
            "```\n"
            f"{modifiers_text}"
            "\n"
            "```\n"
        )
    else:
        modifiers_text = ""
    detector_prompt = PromptTemplate.from_template(
        "You are an expert in code repair, with a specialization in repairing access control and permission-related bugs in smart contracts. \n"
        "\n"
        "{bug_description}\n"
        "\n"
        "Some popular actions to fix the bugs are: \n"
        "{repair_instructions}\n"
        "\n"
        "Using the above description and your own knowledge, repair the below buggy function with your best effort.\n"
        "The buggy smart contract name is {contract_name} and the Solidity version is {solc_version}.\n"
        "\n"
        "The source code of the contract to repair is enclosed in the following code block:\n"
        "```\n"
        "{contract_code}"
        "\n```\n"
        "\n"
        "The source code of the function to repair is enclosed in the following code block:\n"
        "```\n"
        "{buggy_function}"
        "\n```\n"
        "Make sure the function perform the intended logic after repair. Reply only with the fixed function code and nothing else.\n"
    )

    detector_prompt = detector_prompt.partial(
        bug_description=bug_description,
        contract_name=contract_name,
        solc_version=solc_version,
        repair_instructions=repair_instructions,
        contract_code=contract_code,
    )
    memory_prompts.append(detector_prompt.format(buggy_function=buggy_code))
    if get_num_token_from_string("\n".join(memory_prompts)) > code_length_limit.get(
        model_name
    ):
        write_file = os.path.join(
            bug_info.output_path, f"output_{model_name}{RESULT_SUFFIX}_final.sol"
        )
        with open(write_file, "w") as f:
            f.write("code length is too long")
        return
    llm = ChatOpenAI(model_name=model_name, temperature=0)

    detector_chain = detector_prompt | llm | StrOutputParser()

    # all_result = buggy_code
    all_result = detector_chain.invoke({"buggy_function": buggy_code})

    memory_results.append(all_result)
    # with open(log_file, "w") as f:
    #     f.write(json.dumps(all_result))
    # print ("all result ", all_result)
    current_iteration = 0
    write_file = os.path.join(
        bug_info.output_path,
        f"output_{model_name}{RESULT_SUFFIX}_{current_iteration}.sol",
    )
    patched_code, patched_file = process_repair_result(
        all_result, contract_code, bug_info, write_file
    )

    compilation_result = compile_contract(patched_code, bug_info=bug_info)

    validate_result = validate_repair_result(
        patched_file, bug_info, compilation_result, model_name=model_name
    )
    # print ("compilation result ", compilation_result.success, compilation_result.error_message)

    while current_iteration < MAX_ITERATION:
        if compilation_result.success and validate_result:
            break
        current_iteration += 1
        write_file = os.path.join(
            bug_info.output_path,
            f"output_{model_name}{RESULT_SUFFIX}_{current_iteration}.sol",
        )
        followup_prompt = prepare_followup_prompt(
            memory_prompts, memory_results, compilation_result, validate_result
        )
        followup_chain = followup_prompt | llm | StrOutputParser()
        if get_num_token_from_string(
            followup_prompt.format(extra_context="")
        ) > code_length_limit.get(model_name):
            break
        # print ("followup prompt ", followup_prompt.format(extra_context=""))
        # all_result = buggy_code#f"Test result round {current_iteration}:\n"
        all_result = followup_chain.invoke({"extra_context": ""})
        if "STOP" in all_result or len(all_result) < 10:
            break
        memory_results.append(all_result)
        patched_code, patched_file = process_repair_result(
            all_result, contract_code, bug_info, write_file
        )
        compilation_result = compile_contract(patched_code, bug_info=bug_info)
        validate_result = validate_repair_result(
            patched_file, bug_info, compilation_result, model_name=model_name
        )
        # break
    write_file = os.path.join(
        bug_info.output_path, f"output_{model_name}{RESULT_SUFFIX}_final.sol"
    )
    with open(write_file, "w") as f:
        f.write(patched_code)
    # return all_result.get("analyzer_chain")


def analyze_step_by_step(
    contract_code, model_name="gpt-3.5-turbo-1106", log_file="log.txt"
):
    ...
    return "length of contract code is too long"


def analyze_step_by_step_with_specific_bug_type(
    contract_code,
    model_name="gpt-3.5-turbo-1106",
    log_file="log.txt",
    bug_type="access-control",
):
    ...
    return "length of contract code is too long"


def replace_lines_in_file(filename, new_file_name, start_line, end_line, new_text):
    with open(filename, "r") as file:
        lines = file.readlines()

    # Adjusting line numbers to 0-based indexing
    start_line -= 1
    end_line -= 1

    # Replacing the specified lines
    modified_lines = lines[:start_line] + [new_text + "\n"] + lines[end_line + 1 :]

    # Writing the modified content back to the file
    with open(filename, "w") as file:
        file.writelines(modified_lines)


def get_modifer_text(modifiers_data, contract_code):
    return ""
    # not used
    # modifiers_text = ""
    # if modifiers_data is None:
    #     return modifiers_text
    # modifiers_data = list(modifiers_data.values())[0]
    # lines = contract_code.split("\n")
    # for modifier in modifiers_data:
    #     start_line = modifier.get("loc")[0]
    #     end_line = modifier.get("loc")[2]
    #     modifiers_text +=  "\n".join(lines[start_line-1:end_line])
    # return modifiers_text


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
    for function in function_data:
        # print ("function ", function.get("tag"))
        # print ("match str ", match_str)
        if function.get("info") == function_name:
            # print ("found function ", function)
            if function.get("loc")[2] - function.get("loc")[0] > max_distance:
                # print ("found function ", function)
                max_distance_loc = [function.get("loc")[0], function.get("loc")[2]]
                max_distance = function.get("loc")[2] - function.get("loc")[0]
        if match_str in function.get("tag"):
            print("found function ", function)
            matched_loc = [function.get("loc")[0], function.get("loc")[2]]

    lines = contract_code.split("\n")
    # print (lines)
    # print ("matched loc ", matched_loc)
    # print ("max distance loc ", max_distance_loc)
    if matched_loc[0] != -1:
        function_text = "\n".join(lines[matched_loc[0] - 1 : matched_loc[1]])
        return function_text, matched_loc
    else:
        function_text = "\n".join(lines[max_distance_loc[0] - 1 : max_distance_loc[1]])
        return function_text, max_distance_loc


def get_repair_function(tool_name):
    ...


def repair_one_file(
    file_name,
    bug_info,
    model_name="gpt-3.5-turbo-1106",
    output_file="output.sol",
    log_file="log.txt",
    bug_type="access-control",
):
    contract_code = ""
    with open(file_name, "r", encoding="utf-8") as f:
        contract_code = f.read()

    modifiers_text = ""
    file_path = os.path.dirname(file_name)
    solgrep_modifer_file = os.path.join(file_path, "solgrep_modifier_data.json")
    solgrep_function_file = os.path.join(file_path, "solgrep_function_data.json")
    if os.path.exists(solgrep_modifer_file):
        modifiers_data = json.load(open(solgrep_modifer_file))
    if os.path.exists(solgrep_function_file):
        function_data = json.load(open(solgrep_function_file))
    # print ("modifiers data ", modifiers_data)
    # check solc version and install
    solc_version = bug_info.solc_version
    all_installed_solc_version = [str(f) for f in solcx.get_installed_solc_versions()]
    if solc_version not in all_installed_solc_version and solc_version != "0.4.10":
        print("install new solc version ", solc_version)
        solcx.install_solc(solc_version)
    modifiers_text = get_modifer_text(modifiers_data, contract_code)
    # print ("modifier text ", modifier_text)
    # print ("function data ", function_data)
    function_text, function_loc = get_function_text(
        function_data, contract_code, bug_info.function_name, bug_info.contract_name
    )
    bug_info.start_line = function_loc[0]
    bug_info.end_line = function_loc[1]
    print("bug info ", bug_info)
    print("function text ", function_text)
    if bug_type == "access-control":
        res = repair_agent(
            function_text,
            contract_code,
            modifiers_text,
            bug_info,
            model_name=model_name,
            log_file=log_file,
        )
    else:
        print("not support bug type ", bug_type)


def process_file_wrapper(args):
    # Unpack the arguments
    file_path, bug_info, model_name, output_file, log_file, bug_type = args
    repair_one_file(file_path, bug_info, model_name, output_file, log_file, bug_type)


def process_config_file(
    config_file, model_name="gpt-3.5-turbo-1106", jobs=1, bug_type="access-control"
):
    base_path = os.path.dirname(config_file)
    print("base_path ", base_path)
    with open(config_file) as f:
        files = json.load(f)
    tasks = []
    task_count = 0
    for key_, val_ in files.items():
        print(key_, val_)
        file_path = os.path.join(base_path, val_.get("file"))

        print(file_path)
        repair_path = os.path.join(base_path, f'repair_output/{val_.get("file")}')
        # print (output_path)
        os.makedirs(repair_path, exist_ok=True)
        folder_path = os.path.dirname(file_path)
        output_file = os.path.join(
            repair_path, f"output_{model_name}{RESULT_SUFFIX}.sol"
        )
        log_file = os.path.join(repair_path, f"log_{model_name}{RESULT_SUFFIX}.json")
        # print ("output file ", output_file)
        # print ("log file ", log_file)
        bug_info = BugInfo(
            function_name=val_.get("buggy_function"),
            tool_name=val_.get("tool"),
            main_contract_name=val_.get("contract")[0],
            contract_name=val_.get("buggy_contract"),
            solc_version=val_.get("version"),
            file_path=file_path,
            output_path=repair_path,
        )
        print("bug info ", bug_info)
        tasks.append((file_path, bug_info, model_name, output_file, log_file, bug_type))
        task_count += 1
        # if task_count >= 4:
        # break
    if jobs == 1:
        # do sequential processing
        for task in tasks:
            start = time.time()
            process_file_wrapper(task)
            end = time.time()
            print("Time elapsed : ", end - start)
    else:
        # Create a pool of worker processes
        with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
            # Map the process_file_wrapper function to the tasks
            pool.map(process_file_wrapper, tasks)


if __name__ == "__main__":
    # set_llm_cache(SQLiteCache(database_path=".langchain.db"))
    # set_llm_cache(Redis())
    # redis_client = redis.Redis.from_url("redis://localhost:6379")
    # set_llm_cache(RedisCache(redis_client))
    # get argument from command line
    # python <file>.py <file_name> -m <model_name> -o <output_file> -l <log_file> -j <number of processes> -t <bug type>
    # use argparse to parse arguments
    parser = argparse.ArgumentParser(description="Process some arguments.")

    # File name as either a positional argument or with a flag
    parser.add_argument(
        "-f", "--file", dest="file_name", type=str, help="Name of the file to process"
    )
    parser.add_argument(
        "positional_file_name",
        nargs="?",
        type=str,
        help="Name of the file to process (positional argument)",
    )

    # Model name must be specified with a flag
    parser.add_argument(
        "-m",
        "--model",
        dest="model_name",
        type=str,
        required=False,
        default="gpt-3.5-turbo-1106",
        help="Name of the model to use",
    )

    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        type=str,
        required=False,
        default="output.json",
    )
    parser.add_argument(
        "-l", "--log", dest="log_file", type=str, required=False, default="log.txt"
    )
    parser.add_argument(
        "-j", "--jobs", dest="jobs", type=int, required=False, default=1
    )
    parser.add_argument(
        "-t",
        "--type",
        dest="bug_type",
        help="access-control, arbitrary-external-call",
        type=str,
        required=False,
        default="access-control",
    )
    parser.add_argument("--suffix", dest="suffix", type=str, required=False, default="")
    args = parser.parse_args()
    RESULT_SUFFIX = args.suffix
    # Use the file name provided by either the flag or the positional argument
    file_name = args.file_name or args.positional_file_name
    log_file = args.log_file
    output_file = args.output_file
    jobs = args.jobs
    bug_type = args.bug_type
    if ".json" in file_name:
        process_config_file(
            file_name, model_name=args.model_name, jobs=jobs, bug_type=bug_type
        )
        exit(0)
    # print ("Detection result ",res)
