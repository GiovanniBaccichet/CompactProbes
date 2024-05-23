import pandas as pd


def generate_thresholds_df(bitmasks: set, granularity: int) -> pd.DataFrame:
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
        max_dec_value = 2**threshold

        if max_dec_value % granularity != 0:
            raise ValueError(
                "The length of maximum decimal value representable by the bitmask is not a multiple of the granularity."
            )

        # thresholds = list(range(threshold + 1))  # Include 0 to the count of '1's
        thresholds = list(range(0, max_dec_value + 1, granularity))

        data.append((bitmask, thresholds))

    return pd.DataFrame(data, columns=["filters", "thresholds"])

def binary_to_range(binary_string):
    indices = [i for i, bit in enumerate(binary_string) if bit == '1']
    if indices:
        return [indices[0], indices[-1] + 1]  # return range [start, end)
    else:
        return []

def remove_last_threshold(thresholds_list: list) -> list:
    for i in range(len(thresholds_list)):
        del thresholds_list[i][1][-1:-3]
    return thresholds_list
