import pandas as pd

def generate_thresholds(bitmasks: set) -> list:
    """
    Generate thresholds for each bitmask in a set.

    Parameters:
        bitmasks (set): A set containing the bitmasks.

    Returns:
        list: A list of tuples where each tuple contains a list of bitmasks sharing the same threshold list, and their corresponding threshold list in decimal format.
    """
    threshold_dict = {}
    for bitmask in bitmasks:
        # threshold = bitmask.count("1")
        threshold = bitmask.count("1")
        if threshold in threshold_dict:
            threshold_dict[threshold].append(bitmask)
        else:
            threshold_dict[threshold] = [bitmask]

    return [
        (bitmasks, [int(bitmask, 2) for bitmask in bitmasks], list(range(threshold + 1)))
        for threshold, bitmasks in threshold_dict.items()
    ]

def generate_thresholds_df(bitmasks: set) -> pd.DataFrame:
    """
    Generate a DataFrame with filters and corresponding thresholds.

    Parameters:
        bitmasks (set): A set containing the bitmasks.

    Returns:
        pandas.DataFrame: DataFrame with two columns - 'filters' and 'thresholds'.
    """
    data = []
    for bitmask in bitmasks:
        threshold = bitmask.count("1")
        thresholds = list(range(threshold + 1))  # Include 0 to the count of '1's
        data.append((bitmask, thresholds))

    return pd.DataFrame(data, columns=['filters', 'thresholds'])


def remove_last_threshold(thresholds_list: list) -> list:
    for i in range(len(thresholds_list)):
        del thresholds_list[i][1][-1:-3]
    return thresholds_list
