def generate_thresholds(bitmasks: set) -> list:
    """
    Generate thresholds for each bitmask in a set.

    Parameters:
        bitmasks (set): A set containing the bitmasks.

    Returns:
        list: A list of tuples where each tuple contains a list of bitmasks sharing the same threshold list, and their corresponding threshold list.
    """
    threshold_dict = {}
    for bitmask in bitmasks:
        threshold = bitmask.count("1")
        if threshold in threshold_dict:
            threshold_dict[threshold].append(bitmask)
        else:
            threshold_dict[threshold] = [bitmask]

    return [
        (bitmasks, list(range(threshold + 1)))
        for threshold, bitmasks in threshold_dict.items()
    ]


def remove_last_threshold(thresholds_list: list) -> list:
    for i in range(len(thresholds_list)):
        del thresholds_list[i][1][-1:-3]
    return thresholds_list
