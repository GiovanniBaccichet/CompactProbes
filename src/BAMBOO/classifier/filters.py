import numpy as np

def calculate_filter_width(filter: str) -> int:
    filter_start, filter_end = filter[0].split(":")
    width = int(filter_end) - int(filter_start)
    return width

def filter_to_vector(filter_str : str) -> np.ndarray:
    # Convert the string to a list of integers
    nums = [1 if char == '1' else -1 if char == '0' else 0 for char in filter_str]

    # Reshape the list into a column vector
    vector = np.array(nums).reshape(-1, 1)

    return vector