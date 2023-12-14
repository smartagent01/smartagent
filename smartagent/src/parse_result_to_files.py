import json
import os
import re
import sys

result_dir = "../samples/access_control/tool_output"
json_file = "../samples/access_control/file_config.json"
output_path = "../samples/access_control/parsed_tool_output/"

# make dir if not exist
if not os.path.exists(output_path):
    os.makedirs(output_path)
# base_dir = os.path.dirname(os.path.abspath(json_file))
with open(json_file, "r") as f:
    all_files = json.load(f)
print(len(all_files))
tool_output_file = {
    "achecker": "achecker_output.txt",
    "sailfish": "sailfish_output.txt",
    "spcon": "spcon_output.txt",
    "mythril": "mythril/result.json",
    "semgrep": "semgrep/result.json",
    "slither": "slither/result.json",
    "slither_raw": "slither/slither_raw.json",
    "gpt4": "output_gpt-4-1106-preview.json",
    "gpt3": "output_gpt-3.5-turbo-1106.json",
    "gpt3_run2": "output_gpt-3.5-turbo-1106run2.json",
    "gpt4_run2": "output_gpt-4-1106-previewrun2.json",
}
# samples:
# spcon : CRITICAL:spcon.symExec:Permission Bug: find an attack sequence ['setOwner', 'lockBalances']
# Achecker : Violated access control check in function freezeAccount(address,bool)
# 	            ( 2333)  91d:	57	-2 +0 = -2	JUMPI
#               +--Attacker can make changes to AC item {0} in function owned()

# mythril:  "name": "Dependence on tx.origin (SWC 115)", "name" : SWC 105 SWC 106
# mythril reentrancy : State access after external call (SWC 107)
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


def parse_slither_result_smartbugs(all_files, result_dir):
    all_findings = {}
    for key_, val_ in all_files.items():
        file_path = val_["file"]
        result_path = os.path.join(result_dir, file_path)
        slither_output = os.path.join(result_path, tool_output_file["slither"])
        if not os.path.exists(slither_output):
            continue
        with open(slither_output, "r") as f:
            slither_result = json.load(f)
            findings = slither_result["findings"]
            for finding in findings:
                if finding["name"] in access_control_key_words["slither"]:
                    print(key_, finding.get("name"), finding.get("message"))
                    print(
                        finding.get("contract"),
                        finding.get("function"),
                        finding.get("line"),
                        finding.get("line_end"),
                    )
                    all_findings[key_] = finding
    return all_findings


def parse_slither_result(all_files, result_dir, smartbugs=False):
    if smartbugs:
        return parse_slither_result_smartbugs(all_files, result_dir)
    else:
        return parse_slither_result_raw_json(all_files, result_dir)


def parse_slither_result_raw_json(all_files, result_dir):
    all_findings = {}
    for key_, val_ in all_files.items():
        file_path = val_["file"]
        result_path = os.path.join(result_dir, file_path)
        slither_output = os.path.join(result_path, tool_output_file["slither_raw"])
        if not os.path.exists(slither_output):
            continue
        with open(slither_output, "r") as f:
            slither_result = json.load(f)
            findings = slither_result.get("results").get("detectors")
            if not findings:
                continue
            for finding in findings:
                if finding["check"] in access_control_key_words["slither"]:
                    elements = finding.get("elements")
                    for element in elements:
                        if element.get("type") == "function":
                            source_mapping = element.get("source_mapping")
                            function_name = element.get("name")
                            print(key_, finding)
                            # print (key_, finding.get('name'), finding.get('description'))
                            # print (finding.get('contract'), finding.get('function'), finding.get('line'), finding.get('line_end') )
                            new_finding = {
                                "name": finding["check"],
                                "message": finding["description"],
                                "function": function_name,
                                # "line" : source_mapping.get("lines")[0],
                                # "line_end" : source_mapping.get("lines")[-1],
                            }
                            all_findings[key_] = new_finding
                            break
    return all_findings


def parse_semgrep_result(all_files, result_dir):
    all_findings = {}
    for key_, val_ in all_files.items():
        file_path = val_["file"]
        result_path = os.path.join(result_dir, file_path)
        semgrep_output = os.path.join(result_path, tool_output_file["semgrep"])
        if not os.path.exists(semgrep_output):
            continue
        with open(semgrep_output, "r") as f:
            semgrep_result = json.load(f)
            findings = semgrep_result["findings"]
            for finding in findings:
                # print (finding['name'], finding['message'], finding['line'])
                if finding["category"] == "security":
                    # if finding['name'] in access_control_key_words['semgrep']:
                    print(
                        key_,
                        finding.get("name"),
                        finding.get("message"),
                        finding.get("line"),
                    )
                    all_findings[key_] = finding

    return all_findings


def parse_mythril_result(all_files, result_dir):
    all_findings = {}
    for key_, val_ in all_files.items():
        file_path = val_["file"]
        result_path = os.path.join(result_dir, file_path)
        mythril_output = os.path.join(result_path, tool_output_file["mythril"])
        if not os.path.exists(mythril_output):
            continue
        with open(mythril_output, "r") as f:
            mythril_result = json.load(f)
            findings = mythril_result["findings"]
            for finding in findings:
                # print (finding['name'], finding['message'], finding['line'])
                # special case for mythril as name is longer than keyword
                for key_word in access_control_key_words["mythril"]:
                    if key_word in finding["name"]:
                        # print (key_, finding.get('name'), finding.get('message'), finding.get('function'))
                        all_findings[key_] = finding

    return all_findings


def parse_spcon_result(all_files, result_dir):
    all_findings = {}
    for key_, val_ in all_files.items():
        file_path = val_["file"]
        result_path = os.path.join(result_dir, file_path)
        spcon_output = os.path.join(result_path, tool_output_file["spcon"])
        if not os.path.exists(spcon_output):
            continue
        with open(spcon_output, "r") as f:
            spcon_result = f.readlines()
            matched = False
            for line in spcon_result:
                if access_control_key_words["spcon"] in line:
                    match = re.search(r"\['(.*?)'\]", line)
                    # Parse and split the array if found
                    array = match.group(1).split("', '") if match else []
                    matched = True
                    print(key_, line, array[0])
                    all_findings[key_] = {"message": line, "function": array[0]}
            if not matched:
                # print ("not matched", key_)
                # print (spcon_result)
                full_text = "\n".join(spcon_result)
                if "INFO:spcon.symExec:test sequence timeout" in full_text:
                    # special case
                    print("special case")
                    pattern = r"INFO:spcon.symExec:Test Sequence: \['(\w+)'\]"
                    match = re.search(pattern, full_text)
                    # print (match)
                    if match:
                        function_name = match.group(1)
                        print(key_, function_name)
                        all_findings[key_] = {
                            "message": "Test sequence found but SymEx timeout",
                            "function": function_name,
                        }

    print(all_findings)
    return all_findings


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


def parse_achecker_result(all_files, result_dir):
    all_findings = {}
    for key_, val_ in all_files.items():
        file_path = val_["file"]
        result_path = os.path.join(result_dir, file_path)
        achecker_output = os.path.join(result_path, tool_output_file["achecker"])
        if not os.path.exists(achecker_output):
            continue
        with open(achecker_output, "r") as f:
            achecker_result = f.readlines()
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
                        # print ("extracted_function_name ",extracted_function_name)
                        # print (key_, line, extracted_function_name)
                if len(tx_sequence_buffer) > 0:
                    print(key_, tx_sequence_buffer)
                    if key_ not in all_findings:
                        all_findings[key_] = {
                            "message": message_buffer[0],
                            "function": tx_sequence_buffer[0],
                        }

    return all_findings


def parse_gpt_result(all_files, result_dir, tool_name):
    all_findings = {}
    for key_, val_ in all_files.items():
        file_path = val_["file"]
        result_path = os.path.join(result_dir, file_path)
        gpt_result = os.path.join(result_path, tool_output_file[tool_name])
        if not os.path.exists(gpt_result):
            print("result not found ", key_)
            continue

        with open(gpt_result, "r") as f:
            parts = [part.split("\n")[::-1] for part in f.read().split("\n\n")]
            final_result = []
            for part in parts:
                lines = [line for line in part if line.strip() and line != "```"]
                if len(lines) < 2:
                    continue

                if re.match(
                    r"\d+\..*", lines[1]
                ):  # treat as patten: 1. fname\n - message ...
                    for msg_fname in [
                        lines[i : i + 2] for i in range(0, len(lines), 2)
                    ]:
                        if len(msg_fname) < 2:
                            print("ignore", msg_fname)
                            continue
                        msg, fname = msg_fname
                        fname = fname.split(".")[-1].strip()
                        final_result.append(dict(function=fname, message=msg))
                    continue

                # treat as pattern: fname\n\fname\n message ...
                message = lines[0]
                functions = lines[1:]
                for function in functions:
                    fname = [
                        name.strip(""""'`""")
                        for name in function.split()
                        if name.lower() != "the" and name != "function"
                    ][0]
                    final_result.append(dict(function=fname, message=message))
            if len(final_result) > 0:
                all_findings[key_] = final_result
    return all_findings


def parse_tool(tool_name, all_files, result_dir):
    if tool_name == "slither":
        return parse_slither_result(all_files, result_dir)
    elif tool_name == "semgrep":
        return parse_semgrep_result(all_files, result_dir)
    elif tool_name == "mythril":
        return parse_mythril_result(all_files, result_dir)
    elif tool_name == "spcon":
        return parse_spcon_result(all_files, result_dir)
    elif tool_name == "achecker":
        return parse_achecker_result(all_files, result_dir)
    elif "gpt" in tool_name:
        return parse_gpt_result(all_files, result_dir, tool_name)
    else:
        print("Tool name not found")
        return None


# all_tools = ["slither", "semgrep", "mythril", "spcon", "achecker"]
all_tools = ["gpt3"]
# all_tools = [ "achecker"]
for tool in all_tools:
    res = parse_tool(tool, all_files, result_dir)
    all_addresses = {}
    print("Processing tool ", tool, len(res))
    print(output_path + tool + "_addresses.json")
    for key_, val_ in res.items():
        # print (key_, val_['function'], val_['message'])
        # all_files[key_.split("/")[0]]['tool'] = tool
        print(key_)
        all_addresses[key_] = []
        if type(val_) == list:
            for finding in val_:
                all_addresses[key_].append(
                    {
                        "location": finding["function"].split("(")[0],
                        "message": finding["message"],
                    }
                )
        else:
            if "function" not in val_:
                all_addresses[key_].append(
                    {"location": val_["line"], "message": val_["message"]}
                )
            else:
                all_addresses[key_].append(
                    {
                        "location": val_["function"].split("(")[0],
                        "message": val_["message"],
                    }
                )
    json.dump(
        all_addresses, open(output_path + tool + "_addresses.json", "w"), indent=2
    )


parse_slither_result(all_files, result_dir)
# parse_semgrep_result(all_files, result_dir)
parse_mythril_result(all_files, result_dir)
parse_spcon_result(all_files, result_dir)
parse_achecker_result(all_files, result_dir)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide the path to the config file e.g. ../samples/access_control/file_config.json")
        exit(0)
    json_file = sys.argv[1]
    base_path = os.path.dirname(os.path.abspath(json_file))
    result_dir = f"{base_path}/tool_output"
    output_path = f"{base_path}/parsed_tool_output/"
