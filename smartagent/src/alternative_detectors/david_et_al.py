"""
Reproducing paper https://arxiv.org/pdf/2306.12338.pdf
"""
import argparse
from langchain.llms import OpenAI
from langchain.chat_models import ChatOpenAI
from utils.vuln_descriptions_david_et_al import vuln_descriptions
from utils.preprocessing import smartbugs_preprocess
from langchain.prompts import ChatPromptTemplate
from langchain.prompts import PromptTemplate
from langchain.schema import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough

# Remember to !export OPEN_AI_API_KEY=...
vul_list = ["Reentrancy", "Integer overflow or underflow"]


def binary_mode(source_code, model_name="gpt-3.5-turbo-1106"):
    binary_classification = PromptTemplate.from_template(
        """
    You are an AI smart contract auditor that excels at finding vulnerabilities in blockchain smart contracts. Review the following smart contract code in detail and very thoroughly.
    Think step by step, carefully. Is the following smart contract vulnerable to '{vulnerability_type}' attacks? Reply with YES or NO only.
    Do not be verbose. Think carefully but only answer with YES or NO! To help you, find here a definition of a '{vulnerability_type}' attack: {vulnerability_description}
    Source code: {source_code}
    """
    )
    final_res = {vul: False for vul in vul_list}
    for vuln in vul_list:
        vuln_description = vuln_descriptions[vuln]
        # prompt = binary_classification.format(vulnerability_type=vuln, vulnerability_description=vuln_description, source_code=source_code)
        # print (prompt)
        llm = ChatOpenAI(model_name=model_name, temperature=0)
        chain = binary_classification | llm | StrOutputParser()
        res = chain.invoke(
            {
                "vulnerability_type": vuln,
                "vulnerability_description": vuln_description,
                "source_code": source_code,
            }
        )
        if res == "YES":
            print("Found vulnerability: ", vuln)
            final_res[vuln] = True
    print("final res ")
    print(final_res)
    return final_res


def chain_of_thought_mode(source_code, model_name="gpt-3.5-turbo-1106"):
    system_instruction = PromptTemplate.from_template(
        """
        You are an AI smart contract auditor
        that excels at finding vulnerabilities in blockchain
        smart contracts. Review the following smart
        contract code in detail and very thoroughly.
        """
    )

    query_cot_1 = PromptTemplate.from_template(
        """
        You are the best solidity security expert in the world. Perform a proper security audit of this contract, identify critical issues that can lead to loss of funds, pay special attention to logic issues.

        It makes sense to audit each function independently and then see how they link to other functions.

        First, read each function critically and identify critical security issues that can lead to loss of funds.

        {source_code}
        """
    )

    query_cot_2 = PromptTemplate.from_template(
        "Q: Can you check each function independently one after the other?"
    )

    query_cot_3 = PromptTemplate.from_template(
        "Q: Can you do a second check, this time try to understand what each function does?"
    )
    ...


def process_one_file(file_name, mode="binary", model_name="gpt-3.5-turbo-1106"):
    contract_code = ""
    with open(file_name, "r", encoding="utf-8") as f:
        contract_code = f.read()

    processed_code = smartbugs_preprocess(contract_code)
    if not processed_code:
        return ""

    if mode == "binary":
        print("use binary mode")
        return binary_mode(processed_code, model_name=model_name)
    else:
        print("use chain of thought mode")
        return chain_of_thought_mode(processed_code, model_name=model_name)


# process_one_file("samples/reentrancy/reentrancy_dao.sol")

if __name__ == "__main__":
    # get argument from command line
    # python david_et_al.py <file_name> <model_name> <mode>
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
    parser.add_argument(
        "-t", "--type", dest="mode", type=str, required=False, default="binary"
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

    args = parser.parse_args()

    # Use the file name provided by either the flag or the positional argument
    file_name = args.file_name or args.positional_file_name

    if not file_name:
        print("File name is not provided")
        print("Processing test file samples/access_control/TempleDao.sol")
        res = process_one_file(
            "../samples/access_control/TempleDao.sol",
            model_name=args.model_name,
            mode=args.mode,
        )
        print("Detection result ", res)
    else:
        res = process_one_file(file_name, model_name=args.model_name, mode=args.mode)
        print("Detection result ", res)
