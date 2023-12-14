"""
smart-detector.py detecting bugs of smart contracts. currently support access control bugs
"""
import os
import subprocess
import sys
import json
import argparse
import multiprocessing
from multiprocessing import Pool

# import redis
from langchain.llms import OpenAI
from langchain.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.schema import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.cache import SQLiteCache

# from langchain.cache import RedisCache
from langchain.globals import set_llm_cache
from utils.utils import get_num_token_from_string

# from utils.preprocessing import smartbugs_preprocess
# models : [gpt-4-1106-preview, gpt-3.5-turbo-1106]
# https://python.langchain.com/docs/modules/chains/foundational/sequential_chains

# the prompt is about 128 tokens
code_length_limit = {
    "gpt-4-1106-preview": 128000,
    "gpt-3.5-turbo-1106": 16000,
    "llama": 4000,
}
RESULT_SUFFIX = ""


def analyze_full_file(
    contract_code, model_name="gpt-3.5-turbo-1106", log_file="log.txt"
):
    prompt_data = json.load(open("prompt_data/prompt_template.json"))
    llm_detector_prompts = prompt_data.get("llm-detector")
    # llm_analyzer_prompts = prompt_data.get('llm-output-analyzer')
    bug_type = "access control"
    bug_description = llm_detector_prompts.get("bug-description")
    bug_samples = llm_detector_prompts.get("bug-sample")
    sample_contract = llm_detector_prompts.get("sample-contract")
    # print ("bug samples ", bug_samples)
    if type(bug_samples) == list:
        bug_samples = "\n ".join(bug_samples)
    sample_contract_text = ""
    if sample_contract:
        sample_contract_text = (
            "\n Sample buggy contract: \n" + "\n".join(sample_contract) + "\n"
        )
    detector_prompt = PromptTemplate.from_template(
        "You are an expert vulnerability detector specialized in access control and permission related bugs for smart contracts.\n"
        "\n"
        "{bug_description}\n"
        "\n"
        "Some common (but nonexhaustive) bug patterns are: \n"
        "{bug_samples}\n"
        "\n"
        "Using the above description and your own knowledge, detect if the code has any access control bugs.\n"
        "The source code is enclosed in the following code block:\n"
        "```\n"
        "{smartcontract_code}"
        "\n"
        "Let’s think step by step.\n"
    )

    detector_prompt = detector_prompt.partial(
        bug_description=bug_description, bug_samples=bug_samples
    )
    # analyzer_instruction = llm_analyzer_prompts.get('instruction')
    analyzer_prompt = PromptTemplate.from_template(
        "You are a semantic analyzer of text specialized in identifying access control bugs in smart contracts.\n"
        "\n"
        "{bug_description}\n"
        "\n"
        "\n"
        "Some common (but nonexhaustive) bug patterns are: \n"
        "{bug_samples}\n"
        "\n"
        "The following text contains the results of a vulnerability detection analysis for a smart contract, focusing on access control related bugs.\n"
        "Parse the output to print out the functions having bugs.\n"
        "Your output should include only the buggy function's name and a concise, one-sentence explanation of why the bug occurs.\n"
        "Only print the buggy function name and the message in separate lines. The text to analyze is as follows:\n"
        "```\n"
        "{detector_output}\n"
        "```\n"
    )
    analyzer_prompt = analyzer_prompt.partial(
        bug_description=bug_description, bug_samples=bug_samples
    )

    llm = ChatOpenAI(model_name=model_name, temperature=0)

    # uncomment to get intermediate results
    detector_chain = detector_prompt | llm | StrOutputParser()
    analyzer_chain = analyzer_prompt | llm | StrOutputParser()
    chain = {"detector_output": detector_chain} | RunnablePassthrough.assign(
        analyzer_chain=analyzer_chain
    )

    all_result = chain.invoke({"smartcontract_code": contract_code})
    with open(log_file, "w") as f:
        f.write(json.dumps(all_result))
    # print ("all result ", all_result)
    return all_result.get("analyzer_chain")


bug_type_name_mapping = {
    "access-control": "access control",
}
bug_type_key_mapping = {
    "access-control": "llm-detector",
}


def analyze_full_file_with_specific_bug_type(
    contract_code,
    model_name="gpt-3.5-turbo-1106",
    log_file="log.txt",
    bug_type="access-control",
):
    prompt_data = json.load(open("prompt_data/prompt_template.json"))
    prompt_data_key = bug_type_key_mapping.get(bug_type)

    llm_detector_prompts = prompt_data.get(prompt_data_key)
    if not llm_detector_prompts:
        print("bug type not supported")
        return None
    # llm_analyzer_prompts = prompt_data.get('llm-output-analyzer')
    bug_type = bug_type_name_mapping.get(bug_type)
    bug_description = llm_detector_prompts.get("bug-description")
    bug_samples = llm_detector_prompts.get("bug-sample")
    sample_contract = llm_detector_prompts.get("sample-contract")
    print("bug samples ", bug_samples)
    print("bug description ", bug_description)
    sample_contract_text = ""
    if sample_contract:
        sample_contract_text = "\n Sample buggy contract: \n" + sample_contract + "\n"
    if type(bug_samples) == list:
        bug_samples = "\n ".join(bug_samples)
    detector_prompt = PromptTemplate.from_template(
        "You are an expert vulnerability detector specialized in {bug_name} bugs for smart contracts.\n"
        "\n"
        "{bug_description}\n"
        "\n"
        "Some common (but nonexhaustive) bug patterns are: \n"
        "{bug_samples}\n"
        "\n"
        "{sample_contract_text}"
        "\n"
        "Using the above description and your own knowledge, detect if the code has any {bug_name} bugs.\n"
        "The source code is enclosed in the following code block:\n"
        "```\n"
        "{smartcontract_code}"
        "\n"
        "\n"
        "Let’s think step by step.\n"
    )
    detector_prompt = detector_prompt.partial(
        bug_description=bug_description,
        bug_samples=bug_samples,
        bug_name=bug_type,
        sample_contract_text=sample_contract_text,
    )
    # analyzer_instruction = llm_analyzer_prompts.get('instruction')
    analyzer_prompt = PromptTemplate.from_template(
        "You are a semantic analyzer of text specialized in identifying {bug_name} bugs in smart contracts.\n"
        "\n"
        "{bug_description}\n"
        "\n"
        "\n"
        "Some common (but nonexhaustive) bug patterns are: \n"
        "{bug_samples}\n"
        "\n"
        "The following text contains the results of a vulnerability detection analysis for a smart contract, focusing on {bug_name} related bugs.\n"
        "Parse the output to print out the functions having bugs.\n"
        "Your output should include only the buggy function's name and a concise, one-sentence explanation of why the bug occurs.\n"
        "Only print the buggy function name and the message in separate lines. The text to analyze is as follows:\n"
        "```\n"
        "{detector_output}\n"
        "```\n"
    )
    analyzer_prompt = analyzer_prompt.partial(
        bug_description=bug_description, bug_samples=bug_samples, bug_name=bug_type
    )

    llm = ChatOpenAI(model_name=model_name, temperature=0, cache=False)

    # uncomment to get intermediate results
    detector_chain = detector_prompt | llm | StrOutputParser()
    analyzer_chain = analyzer_prompt | llm | StrOutputParser()
    chain = {"detector_output": detector_chain} | RunnablePassthrough.assign(
        analyzer_chain=analyzer_chain
    )

    all_result = chain.invoke({"smartcontract_code": contract_code})
    with open(log_file, "w") as f:
        f.write(json.dumps(all_result))
    # print ("all result ", all_result)
    return all_result.get("analyzer_chain")


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


def process_one_file(
    file_name,
    model_name="gpt-3.5-turbo-1106",
    output_file="output.json",
    log_file="log.txt",
    bug_type="access-control",
):
    print ("process_one_file ", file_name)
    contract_code = ""
    with open(file_name, "r", encoding="utf-8") as f:
        contract_code = f.read()
    num_token = get_num_token_from_string(contract_code, model=model_name)
    print("num token of contract source code ", num_token)
    if num_token > code_length_limit.get(model_name, 2048):
        print(f"Contract source code is too long for the model: {num_token} tokens")
        # res = analyze_step_by_step(contract_code, model_name=model_name, log_file=log_file)
        if bug_type == "access-control":
            res = analyze_step_by_step(
                contract_code, model_name=model_name, log_file=log_file
            )
        else:
            res = analyze_step_by_step_with_specific_bug_type(
                contract_code,
                model_name=model_name,
                log_file=log_file,
                bug_type=bug_type,
            )
    else:
        if bug_type == "access-control":
            res = analyze_full_file(
                contract_code, model_name=model_name, log_file=log_file
            )
        else:
            res = analyze_full_file_with_specific_bug_type(
                contract_code,
                model_name=model_name,
                log_file=log_file,
                bug_type=bug_type,
            )
    if res:
        with open(output_file, "w") as f:
            f.write(res)
    else:
        with open(output_file, "w") as f:
            f.write(json.dumps({"error": "no result"}))


def process_file_wrapper(args):
    # Unpack the arguments
    file_path, model_name, output_file, log_file, bug_type = args
    process_one_file(file_path, model_name, output_file, log_file, bug_type)


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
        output_path = os.path.join(base_path, f'tool_output/{val_.get("file")}')
        # print (output_path)
        os.makedirs(output_path, exist_ok=True)
        folder_path = os.path.dirname(file_path)
        output_file = os.path.join(
            output_path, f"output_{model_name}{RESULT_SUFFIX}.json"
        )
        log_file = os.path.join(output_path, f"log_{model_name}{RESULT_SUFFIX}.json")
        print("output file ", output_file)
        print("log file ", log_file)
        tasks.append((file_path, model_name, output_file, log_file, bug_type))
        task_count += 1
        # if task_count >= 4:
        #     break
    if jobs == 1:
        # do sequential processing
        for task in tasks:
            process_file_wrapper(task)
    else:
        # Create a pool of worker processes
        with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
            # Map the process_file_wrapper function to the tasks
            pool.map(process_file_wrapper, tasks)


if __name__ == "__main__":
    # set_llm_cache(SQLiteCache(database_path=".langchain.db"))
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
    if not file_name:
        print("File name is not provided")
        print("Processing test file samples/access_control/MorphToken.sol")
        res = process_one_file(
            "../samples/access_control/MorphToken/MorphToken.sol",
            model_name=args.model_name,
            output_file=output_file,
            log_file=log_file,
            bug_type=bug_type,
        )
        # print ("Detection result ",res)
    else:
        res = process_one_file(
            file_name,
            model_name=args.model_name,
            output_file=output_file,
            log_file=log_file,
            bug_type=bug_type,
        )
        # print ("Detection result ",res)
