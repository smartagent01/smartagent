import json
import os

all_address = []
all_detected_address = []
address_key_mapping = {}
all_files = {}


def process_tool_output(tool_output, all_files_path):
    base_path = os.path.dirname(os.path.abspath(all_files_path))
    # FN_set = []
    TP_set = []
    FP_set = []
    with open(tool_output) as f:
        tool_output = json.load(f)
        # print (tool_output)
        for key, item in tool_output.items():
            if key.lower() not in all_address:
                continue
            all_json_key = address_key_mapping[key.lower()]
            file_name = all_files[all_json_key]["file"].split("/")[-1]
            bug_info_path = os.path.join(
                base_path, all_files[all_json_key]["file"].split("/")[0]
            )
            bug_info_file = os.path.join(bug_info_path, "bug_info.json")
            with open(bug_info_file) as f:
                bug_info = json.load(f)[0]
                for bug_ in item:
                    # print (bug_)
                    if type(bug_.get("location")) == int:
                        if bug_.get("location") >= bug_info.get(
                            "line_start"
                        ) and bug_.get("location") <= bug_info.get("line_end"):
                            TP_set.append(
                                key
                                + " : "
                                + str(bug_.get("location"))
                                + " : "
                                + str(bug_info.get("line_start"))
                                + " : "
                                + str(bug_info.get("function"))
                            )
                        else:
                            FP_set.append(
                                key
                                + " : "
                                + str(bug_.get("location"))
                                + " : "
                                + str(bug_info.get("line_start"))
                                + " : "
                                + str(bug_info.get("function"))
                            )

                    elif (
                        bug_.get("location").split("(")[0].lower()
                        == bug_info.get("function").split("(")[0].lower()
                    ):
                        # print ("match ", key)
                        TP_set.append(
                            key
                            + " : "
                            + bug_.get("location")
                            + " : "
                            + bug_info.get("function")
                        )
                    else:
                        # print ("not match ", key)
                        FP_set.append(
                            key
                            + " : "
                            + bug_.get("location")
                            + " : "
                            + bug_info.get("function")
                        )

    print("Correctly matched bugs", len(TP_set))
    for item in TP_set:
        print(item)
    print("Wrong bugs", len(FP_set))
    # for item in FP_set:
    #     print (item)


# reentrancy
all_files_path = "../Real-Hacks-SunWeb3Sec/access-control/all_files_no_ext_update.json"
with open(all_files_path) as f:
    all_files = json.load(f)
    print(len(all_files))
    for key, item in all_files.items():
        all_address.append(item["address"].lower())
        address_key_mapping[item["address"].lower()] = key

print(all_address)
print("aggregated_gpt3")
process_tool_output(
    "../Real-Hacks-SunWeb3Sec/access-control/parsed_tool_output/aggregated_result_gpt-3.5-turbo-1106.json",
    all_files_path,
)
print("aggregated_gpt3_filtered")
process_tool_output(
    "../Real-Hacks-SunWeb3Sec/access-control/parsed_tool_output/aggregated_result_gpt-3.5-turbo-1106_gpt-3.5-turbo-1106_filtered_final.json",
    all_files_path,
)


print("aggregated_gpt4")
process_tool_output(
    "../Real-Hacks-SunWeb3Sec/access-control/parsed_tool_output/aggregated_result_gpt-4-1106-preview.json",
    all_files_path,
)
print("aggregated_gpt4_filtered")
process_tool_output(
    "../Real-Hacks-SunWeb3Sec/access-control/parsed_tool_output/aggregated_result_gpt-4-1106-preview_gpt-4-1106-preview_filtered_final.json",
    all_files_path,
)
tool_output_2 = (
    "../Real-Hacks-SunWeb3Sec/access-control/parsed_tool_output/slither_addresses.json"
)
