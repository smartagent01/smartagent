import tiktoken
import time
import subprocess
import random
import re
import json


def num_tokens_from_messages(messages, model="gpt-3.5-turbo-0613"):
    """Return the number of tokens used by a list of messages."""
    try:
        encoding = tiktoken.encoding_for_model(model)
    except KeyError:
        print("Warning: model not found. Using cl100k_base encoding.")
        encoding = tiktoken.get_encoding("cl100k_base")
    if "gpt-" in model:
        tokens_per_message = 3
        tokens_per_name = 1
    elif model == "gpt-3.5-turbo-0301":
        tokens_per_message = (
            4  # every message follows <|start|>{role/name}\n{content}<|end|>\n
        )
        tokens_per_name = -1  # if there's a name, the role is omitted
    elif "gpt-3.5-turbo" in model:
        print(
            "Warning: gpt-3.5-turbo may update over time. Returning num tokens assuming gpt-3.5-turbo-0613."
        )
        return num_tokens_from_messages(messages, model="gpt-3.5-turbo-0613")
    elif "gpt-4" in model:
        print(
            "Warning: gpt-4 may update over time. Returning num tokens assuming gpt-4-0613."
        )
        return num_tokens_from_messages(messages, model="gpt-4-0613")
    else:
        raise NotImplementedError(
            f"""num_tokens_from_messages() is not implemented for model {model}. See https://github.com/openai/openai-python/blob/main/chatml.md for information on how messages are converted to tokens."""
        )
    num_tokens = 0
    for message in messages:
        num_tokens += tokens_per_message
        for key, value in message.items():
            num_tokens += len(encoding.encode(value))
            if key == "name":
                num_tokens += tokens_per_name
    num_tokens += 3  # every reply is primed with <|start|>assistant<|message|>
    return num_tokens


def get_num_token_from_string(input_string, model="gpt-3.5-turbo-0613"):
    try:
        encoding = tiktoken.encoding_for_model(model)
    except KeyError:
        print("Warning: model not found. Using cl100k_base encoding.")
        encoding = tiktoken.get_encoding("cl100k_base")

    num_tokens = len(encoding.encode(input_string))
    return num_tokens


# Running the bash script with arguments
# subprocess.run(command, shell=True)
def run_command(command, time_sleep_max=0):
    try:
        # Execute the command and wait for it to complete
        # random sleep to avoid API rate limit for some tools
        if time_sleep_max > 0:
            delay = random.uniform(0, time_sleep_max)
            print("sleep for ", delay)
            time.sleep(delay)
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return command, result.stdout.decode(), result.stderr.decode()
    except subprocess.CalledProcessError as e:
        # Return standard error output if the command fails
        print("error ", e)
        return command, e.stdout.decode(), e.stderr.decode()


achecker_stop_line = (
    "Violated access control check in"  # stop line between tx sequences
)
achecker_stop_line_2 = "Missing access control check in"
access_control_key_words = {
    "achecker": ["Attacker can make changes", "Needed to protect following"],
    "spcon": "CRITICAL:spcon.symExec:Permission Bug",
    "mythril": [
        "SWC 115",
        "SWC 112",
        "SWC 105",
        "SWC 106",
        "External Call To User-Supplied Address (SWC 107)",
    ],
    "semgrep": [
        "erc20-public-transfer",
        "erc20-public-burn",
        "erc721-arbitrary-transferfrom",
        "redacted-cartel-custom-approval-bug",
        "rigoblock-missing-access-control",
        "tecra-coin-burnfrom-bug",
        "superfluid-ctx-injection",
        "arbitrary-low-level-call",
        "proxy-storage-collision",
        "unrestricted-transferownership",
        "msg-value-multicall",
        "delegatecall-to-arbitrary-address",
        "accessible-selfdestruct",
    ],
    "slither": [
        "arbitrary-send",
        "arbitrary-send-erc20-permit",
        "arbitrary-send-eth",
        "arbitrary-send-erc20",
        "protected-vars",
        "unprotected-upgrade",
        "suicidal",
        "controlled-delegatecall",
        "tx-origin",
    ],
}


def extract_achecker_function_name(line):
    match = re.search(r"function (\w+)\(.*?\)", line)
    if match:
        return match.group(1)
    else:
        # Handle the special case for fallback function
        if "function ()" in line:
            return "fallback"
        # Handle the special case for 4byte function identifiers
        elif re.search(r"function ([0-9a-f]{8})", line):
            print("4byte function identifier found")
            print(f"4byte_{line.split()[-1]}")
            return f"4byte_{line.split()[-1]}"
        else:
            return None


def achecker_parser(achecker_result):
    # print ("parse achecker result", achecker_result)
    if "\n" in achecker_result:
        achecker_result = achecker_result.split("\n")
    tx_sequence_buffer = []
    message_buffer = []
    for line in achecker_result:
        if achecker_stop_line in line or achecker_stop_line_2 in line:
            tx_sequence_buffer = []
            message_buffer = []
        for key_word in access_control_key_words["achecker"]:
            if key_word in line:
                # Regular expression to find the function name
                # function_name = re.search(r"function (\w+)\(.*?\)", line)
                # Extract the function name if found
                extracted_function_name = extract_achecker_function_name(line)
                tx_sequence_buffer.append(extracted_function_name)
                message_buffer.append(line)
                # print ("extracted_function_name ", extracted_function_name)
                # print (key_, line, extracted_function_name)
        if len(tx_sequence_buffer) > 0:
            return (False, tx_sequence_buffer[0], message_buffer[0])
    return (True, None, None)


def parse_slither_result(slither_output):
    with open(slither_output, "r") as f:
        slither_result = json.load(f)
        findings = slither_result.get("results").get("detectors")
        if not findings:
            return (True, None, None)
        for finding in findings:
            if finding["check"] in access_control_key_words["slither"]:
                elements = finding.get("elements")
                for element in elements:
                    if element.get("type") == "function":
                        source_mapping = element.get("source_mapping")
                        function_name = element.get("name")
                        print(finding.get("check"))
                        new_finding = {
                            "name": finding["check"],
                            "message": finding["description"],
                            "function": function_name,
                        }
                        return (False, function_name, finding["description"])

    return (True, None, None)


def parse_gpt_result(gpt_result, function_name):
    lines = gpt_result.split("\n")
    for line in lines:
        if function_name in line:
            return (False, function_name, line)
    return (True, None, None)
