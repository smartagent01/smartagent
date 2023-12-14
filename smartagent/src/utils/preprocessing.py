def smartbugs_preprocess(text):
    hints = [
        "vulnerable_at_lines:",
        "// <yes> <report> DENIAL_OF_SERVICE",
        "// <yes> <report> ARITHMETIC",
        "// <yes> <report> BAD_RANDOMNESS",
        "// <yes> <report> ACCESS_CONTROL",
        "// <yes> <report> FRONT_RUNNING",
        "// <yes> <report> REENTRANCY",
        "// <yes> <report> SHORT_ADDRESSES",
        "// <yes> <report> TIME_MANIPULATION",
        "// <yes> <report> UNCHECKED_LL_CALLS",
    ]
    for i in hints:
        text = text.replace(i, "")
    return text

def smartbench_preprocess(text):
    ...