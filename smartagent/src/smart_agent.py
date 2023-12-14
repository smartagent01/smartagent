from langchain.llms import OpenAI
from langchain.chat_models import ChatOpenAI
from langchain.cache import SQLiteCache
from langchain.globals import set_llm_cache
from detector_agent import process_one_file as process_one_file_detector
from detector_agent import process_config_file as process_config_file_detector

from aggregator_agent import process_aggregated_file as process_aggregated_file
from aggregator_agent import process_config_file as process_config_file_aggregator

from repair_agent import process_config_file as process_config_file_repair

# Remember to !export OPEN_AI_API_KEY=...
import argparse
from pathlib import Path


def run_detector_agent(args):
    # Here, you would include the logic for the Detector agent
    print("Running Detector Agent with args:", args)
    file_name = args.file_name or args.positional_file_name
    print ("file_name",file_name)

    log_file = args.log_file
    output_file = args.output_file
    jobs = args.jobs
    bug_type = args.bug_type
    if ".json" in file_name:
        process_config_file_detector(
            file_name, model_name=args.model_name, jobs=jobs, bug_type=bug_type
        )
        exit(0)
    exit(0)
    if not file_name:
        print("File name is not provided")
        print("Processing test file samples/access_control/MorphToken.sol")
        res = process_one_file_detector(
            "../samples/access_control/MorphToken/MorphToken.sol",
            model_name=args.model_name,
            output_file=output_file,
            log_file=log_file,
            bug_type=bug_type,
        )
        # print ("Detection result ",res)
    else:
        res = process_one_file_detector(
            file_name,
            model_name=args.model_name,
            output_file=output_file,
            log_file=log_file,
            bug_type=bug_type,
        )


def run_aggregator_agent(args):
    # Here, you would include the logic for the Aggregator agent
    print("Running Aggregator Agent with args:", args)
    file_name = args.file_name or args.positional_file_name
    log_file = args.log_file
    output_file = args.output_file
    result_dir = args.result_dir
    jobs = args.jobs
    contract_config_path = args.config_file
    # debugging
    if args.config_file != "NA":
        process_aggregated_file(
            contract_config_path,
            file_name,
            model_name=args.model_name,
            log_file=log_file,
        )
        exit()
    if ".json" in file_name:
        process_config_file_aggregator(
            file_name,
            result_dir=result_dir,
            model_name=args.model_name,
            jobs=jobs,
            output_file=output_file,
            log_file=log_file,
        )


def run_repair_agent(args):
    # Here, you would include the logic for the Repair agent
    print("Running Repair Agent with args:", args)
    file_name = args.file_name or args.positional_file_name
    log_file = args.log_file
    output_file = args.output_file
    jobs = args.jobs
    bug_type = args.bug_type
    if ".json" in file_name:
        process_config_file_repair(
            file_name, model_name=args.model_name, jobs=jobs, bug_type=bug_type
        )
        exit(0)
    # print ("Detection result ",res)


def parse_args():
    parser = argparse.ArgumentParser(description="Smart Agent Runner")

    # Common arguments
    parser.add_argument(
        "-a",
        "--agent",
        choices=["detector", "aggregator", "repair"],
        required=True,
        help="Select the agent to run",
    )
    parser.add_argument(
        "-f", "--file", dest="file_name", type=str, help="Name of the file to process"
    )
    parser.add_argument(
        "positional_file_name",
        nargs="?",
        type=str,
        help="Name of the config file to process (positional argument)",
    )
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
        help="access-control",
        type=str,
        required=False,
        default="access-control",
    )
    parser.add_argument("--suffix", dest="suffix", type=str, required=False, default="")

    # Additional arguments for Aggregator agent
    parser.add_argument("-c", "--config", dest="config_file", default="NA", type=str)
    parser.add_argument(
        "-r",
        "--result",
        dest="result_dir",
        help="result from the parent dir of config file",
        type=str,
        required=False,
        default="parsed_tool_output",
    )

    return parser.parse_args()


def main():
    # set_llm_cache(SQLiteCache(database_path=".langchain.db"))
    args = parse_args()

    if args.agent == "detector":
        run_detector_agent(args)
    elif args.agent == "aggregator":
        run_aggregator_agent(args)
    elif args.agent == "repair":
        run_repair_agent(args)
    else:
        print(f"Unknown agent: {args.agent}")


if __name__ == "__main__":
    main()
