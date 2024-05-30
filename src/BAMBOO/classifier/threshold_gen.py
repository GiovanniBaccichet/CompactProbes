import pandas as pd


def generate_thresholds_df(bitmasks: set) -> pd.DataFrame:
    data = []
    for bitmask in bitmasks:
        threshold = sum(1 for char in bitmask if char != '0')
        thresholds = list(range(threshold + 1))  # Include 0 to the count of '1's
        data.append((bitmask, thresholds))

    return pd.DataFrame(data, columns=["filters", "thresholds"])
