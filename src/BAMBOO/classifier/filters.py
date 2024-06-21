import numpy as np

from . import compute_error


def calculate_filter_width(filter_str: str) -> int:
    return len([char for char in filter_str if char != "0"])


def filter_to_vector(filter_str: str) -> np.ndarray:
    # Convert the string to a list of integers
    vector = [1 if char == "1" else -1 if char == "N" else 0 for char in filter_str]

    return vector


def process_filters_chunk(chunk, string_pair_df, weights):
    for _, row in chunk.iterrows():
        filter = row["filters"]
        thresholds = row["thresholds"]
        result = compute_error.matrix_error(string_pair_df, thresholds, filter, weights)
    return result
