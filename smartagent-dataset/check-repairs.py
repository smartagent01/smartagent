# python ./Scripts/check-repairs.py
import glob
import os
import difflib
import json

repaired_files = glob.glob(f'./**/*repair*/**/*_final.sol', recursive=True)
summary = []


def diff_a_b(a, b):
    with open(a) as f:
        a_lines = [line.rstrip() for line in f.readlines()]

    with open(b) as f:
        b_lines = [line.rstrip() for line in f.readlines()]

    label = lambda x: 'repair' if 'repair' in x else 'original'

    diff = difflib.unified_diff(a_lines, b_lines,
                                fromfile=label(a), tofile=label(b),
                                lineterm='')

    diff = list(diff)

    for line in diff:
        print(line)

    return diff

for repaired in repaired_files:
    original = os.path.join(*repaired.split('/')[:-1]).replace('repair_output/', '')
    if not os.path.isfile(original):
        raise Exception(f'ERROR: {original} not found')

    print('-'*30, original.split('/')[-1])
    diff = diff_a_b(original, repaired)

    summary.append(dict(diff=list(diff), original=original, repaired=repaired, is_correct='UNKNOWN'))

# export summary to json file
with open('repair_summary_template.json', 'w') as f:
    json.dump(summary, f, indent=2)
