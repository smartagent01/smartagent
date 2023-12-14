"""
Reproducing paper https://arxiv.org/pdf/2309.05520.pdf
"""
import sys
import argparse
from langchain.llms import OpenAI
from langchain.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.schema import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough

from utils.preprocessing import smartbugs_preprocess

# https://python.langchain.com/docs/modules/chains/foundational/sequential_chains


def process_one_file(file_name, model_name="gpt-3.5-turbo-1106"):
    detector_prompt = PromptTemplate.from_template(
        """You are a vulnerability detector for a smart contract. Here are nine common vulnerabilities.
        First, Reentrancy, also known as or related to race to empty, recursive call vulnerability, call to the unknown.
        Second, Access Control. Third, Arithmetic Issues, also known as integer overflow and integer underflow.
        Fourth, Unchecked Return Values For Low Level Calls, also known as or related to silent failing sends, unchecked-send.
        Fifth, Denial of Service, including gas limit reached, unexpected throw, unexpected kill, access control breached.
        Sixth, Bad Randomness, also known as nothing is secret.
        Seventh, Front-Running, also known as time-of-check vs time-of-use (TOCTOU), race condition, transaction ordering dependence (TOD).
        Eighth, Time manipulation, also known as timestamp dependence.
        Nineth, Short Address Attack, also known as or related to off-chain issues, client vulnerabilities.
        Think step by step, carefully.
        Check the following smart contract for the above vulnerabilities. The input is: \n{smartcontract_code}
        """
    )

    analyzer_prompt = PromptTemplate.from_template(
        """You are a semantic analyzer of text. Here are nine common vulnerabilities.
        First, Reentrancy, also known as or related to race to empty, recursive call vulnerability, call to the unknown.
        Second, Access Control. Third, Arithmetic Issues, also known as integer overflow and integer underflow.
        Fourth, Unchecked Return Values For Low Level Calls, also known as or related to silent failing sends, unchecked-send.
        Fifth, Denial of Service, including gas limit reached, unexpected throw, unexpected kill, access control breached.
        Sixth, Bad Randomness, also known as nothing is secret. Seventh, Front-Running, also known as time-of-check vs time-of-use (TOCTOU), race condition, transaction ordering dependence (TOD).
        Eighth, Time manipulation, also known as timestamp dependence.
        Nineth, Short Address Attack, also known as or related to off-chain issues, client vulnerabilities.
        Think step by step, carefully. The following text is a vulnerability detection result for a smart contract.
        Use 0 or 1 to indicate whether whether there are specific types of vulnerabilities.
        For example: 'Reentrancy: 1'. The input is
        {detector_output}
        """
    )
    llm = ChatOpenAI(model_name=model_name, temperature=0)

    # uncomment to get intermediate results
    # detector_chain = detector_prompt | llm | StrOutputParser()
    # analyzer_chain = analyzer_prompt | llm | StrOutputParser()
    # chain = {"detector_output": detector_chain} | RunnablePassthrough.assign(
    #     analyzer_chain=analyzer_chain
    # )

    chain = (
        {"detector_output": detector_prompt | llm | StrOutputParser()}
        | analyzer_prompt
        | llm
        | StrOutputParser()
    )
    contract_code = ""
    with open(file_name, "r", encoding="utf-8") as f:
        contract_code = f.read()

    processed_code = smartbugs_preprocess(contract_code)
    if not processed_code:
        return ""

    # Todo: post process and check for TF, FP, FN
    return chain.invoke({"smartcontract_code": processed_code})


if __name__ == "__main__":
    # get argument from command line
    # python chong_et_al.py <file_name> <model_name>
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

    args = parser.parse_args()

    # Use the file name provided by either the flag or the positional argument
    file_name = args.file_name or args.positional_file_name

    if not file_name:
        print("File name is not provided")
        print("Processing test file samples/access_control/TempleDao.sol")
        res = process_one_file(
            "../samples/access_control/TempleDao.sol", model_name=args.model_name
        )
        print("Detection result ", res)
    else:
        res = process_one_file(file_name, model_name=args.model_name)
        print("Detection result ", res)
