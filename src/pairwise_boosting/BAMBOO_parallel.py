# %% [markdown]
# # BAMBOO: Binary descriptor based on AsymMetric pairwise BOOsting

# %% [markdown]
# In this notebook we include the implementation of the BAMBOO descriptor to provide a compressed representation of probe requests.

# %% [markdown]
# ## Libraries and Configurations

# %% [markdown]
# Logger

# %%
import logging
from rich.logging import RichHandler

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET",
    format=FORMAT,
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)

log = logging.getLogger("rich")

log.setLevel("CRITICAL")

# %% [markdown]
# Import configuration files

# %%
from configparser import ConfigParser

config = ConfigParser()
config.read("../config.ini")

# %% [markdown]
# Import **data libraries**

# %%
import pandas as pd

# %% [markdown]
# Import **other libraries**

# %%
from rich.progress import Progress
from rich import traceback

traceback.install()

from tqdm import tqdm

# %%
import numpy as np
import math

# %% [markdown]
# Fancy print

# %%
class color:
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    DARKCYAN = "\033[36m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"

# %%
def bold_text(text: str) -> str:
    return str(color.BOLD + str(text) + color.END)

# %% [markdown]
# ## Import Data

# %% [markdown]
# Importing **concatenated columns** and **pairs** datasets

# %%
pairs_df = pd.read_csv("/home/bacci/COMPACT/data/interim/pairs_df.csv", index_col=0)

# %%
pairs_df

# %%
strings_df = pd.read_csv("/home/bacci/COMPACT/data/interim/string_df.csv", index_col=0)
strings_df = strings_df.rename(columns={strings_df.columns[0]: "Probes"})

# %%
strings_df

# %% [markdown]
# Importing bitmask **filters**

# %%
filters_df = pd.read_csv("/home/bacci/COMPACT/data/filters/bitmasks.csv", index_col=0)

# %%
print("Number of filters in the dataset: " + bold_text(filters_df.shape[0]))

# %% [markdown]
# Select only filter corresponding to single columns (drop combinations).

# %%
filters_df = filters_df.head(16).reset_index()

# %% [markdown]
# Getting actual bitmask filters' column

# %%
filters = filters_df["Bitmask"]

# %% [markdown]
# Function to associate a **set of thresholds to each filter**, depending on the number of `1`.

# %%
def generate_thresholds(bitmasks):
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

# %% [markdown]
# **Generating thresholds** from bitmask filters

# %%
thresholds_list = generate_thresholds(filters)

# %%
print("Number of threshold sets: " + bold_text(len(thresholds_list)))

# %% [markdown]
# ### Functions

# %% [markdown]
# The **bitwise AND** function performs said operation on 2 binary strings

# %%
def bitwise_and(bit_str1, bit_str2):
    # Convert bit strings to integers
    int1 = int(bit_str1, 2)
    int2 = int(bit_str2, 2)

    # Perform bitwise AND operation
    result = int1 & int2

    # Convert result back to binary string
    result_str = bin(result)[2:]  # [2:] to remove '0b' prefix

    # Return result
    return result_str.zfill(max(len(bit_str1), len(bit_str2)))

# %% [markdown]
# The **sum filter** takes as input a (binary) string and sums the values

# %%
def sumFilter(bitwise_and: str) -> int:
    sum = 0
    for i in bitwise_and:
        sum += int(i)
    return sum

# %% [markdown]
# **Sign function** returns -1 if negative value

# %%
def sign(number: int) -> int:
    if number < 0:
        return -1
    elif number >= 0:
        return 1

# %% [markdown]
# The **weak classifier** filters a couple of tuples, and given a threshold it, returns +1 or -1

# %%
def weak_classifier(pair: tuple, threshold: int, filter: str) -> int:
    log.debug(pair, threshold, filter)
    filtered1 = sumFilter(bitwise_and(pair[0], filter))
    filtered2 = sumFilter(bitwise_and(pair[1], filter))
    return sign((filtered1 - threshold) * (filtered2 - threshold))

# %% [markdown]
# Implementation of the **Dirach delta** function

# %%
def delta(prediction: int, ground_truth: int) -> int:
    if prediction != ground_truth:
        return 1
    else:
        return 0

# %% [markdown]
# The **get error** function calculates the weighted value of the filter, given the prevision and the ground truth

# %%
def get_error(weigth: float, prediction: int, ground_truth: int) -> float:
    error = weigth * delta(prediction, ground_truth)

    log.debug(f"Weigth {weigth}, Prediction {prediction}, Ground Truth {ground_truth}")

    return error

# %% [markdown]
# ### BAMBOO

# %% [markdown]
# Input:
# - Ground truth relationships $\langle x_{a(n)}, x_{b(n)}; y_n\rangle$
#   - $n=1,..,N$
#   - $y_n \in \{+1, -1\}$
# - A set of filters $\mathcal{H} = \{h_1 , ..., h_F\}$
# - A set of binarization thresholds $\mathcal{T} = \{t_1 , ..., t_T\}$
# 
# Output:
# - A set of $M<F$ filters $[h_{i(1)}, ..., h_{i(M)}]$
# - Corresponding set of binarization thresholds $[t_{j(1)}, ..., t_{j(M)}]$

# %% [markdown]
# Define **BAMBOO input**

def remove_element_by_value(data, value):
    for i in range(len(data)):
        if value in data[i][0]:
            data[i] = ([x for x in data[i][0] if x != value], data[i][1])
            return True  # Element found and removed
    return False  # Element not found

# %%
# Input
dataset = strings_df.copy()
# pairs_index = pairs_df.copy()
pairs_index = pairs_df.head(300)
filters = thresholds_list
M = 3

# Initial weights
weights = np.ones(len(pairs_index)) / len(pairs_index)

# Errors per iteration
errors = {}

# %% [markdown]
# Algorithm implementation

# %%
import multiprocessing
from functools import partial
from tqdm import tqdm
import math

def calculate_errors(filters_entry, pairs_index, dataset, weights, weak_classifier):
    errors = {}
    filters_list, threshold_list = filters_entry
    for filter, thresholds in zip(filters_list, [threshold_list] * len(filters_list)):
        for threshold in thresholds:
            error = 0
            for pair in range(len(pairs_index)):
                prediction = weak_classifier(
                    tuple(dataset.iloc[pairs_index.iloc[pair, 0:2], 0]),
                    threshold,
                    filter,
                )
                error += get_error(
                    weights[pair], prediction, pairs_index.iloc[pair, 2]
                )
            errors[(filter, threshold)] = error
    return errors

def parallel_processing(M, filters, pairs_index, dataset, weights, weak_classifier):
    pool = multiprocessing.Pool()
    errors_list = list(tqdm(pool.imap(partial(calculate_errors, pairs_index=pairs_index, dataset=dataset, weights=weights, weak_classifier=weak_classifier), filters), total=M, desc="Iterations"))
    pool.close()
    pool.join()

    errors = {}
    for e in errors_list:
        errors.update(e)

    # print(errors)
    best_filter, best_threshold = min(errors, key=lambda k: abs(errors[k]))

    print("Best Filter:", best_filter)
    print("Best Threshold:", best_threshold)

    min_error = errors[(best_filter, best_threshold)]
    if min_error == 0:
        min_error = 0.000000000000000000000001
    confidence = math.log(
        (1 - min_error) / min_error
    )  # confidence of the weak classifier
    print("Min error", min_error)
    print("Confidence:", confidence)

    # Asymmetric Weight Update
    for pair in range(len(pairs_index)):
        if pairs_index.iloc[pair, 2] == +1:
            if (
                weak_classifier(
                    tuple(dataset.iloc[pairs_index.iloc[pair, 0:2], 0]),
                    best_threshold,
                    best_filter,
                )
                != pairs_index.iloc[pair, 2]
            ):
                weights[pair] = weights[pair] * math.exp(confidence)

    for pair in range(len(pairs_index)):
        if pairs_index.iloc[pair, 2] == +1:
            weights[pair] = weights[pair] / sum(
                weights[pair]
                for pair in range(len(pairs_index))
                if pairs_index.iloc[pair, 2] == +1
            )

    remove_element_by_value(filters, best_filter)

# Assuming other functions like get_error and remove_element_by_value are defined elsewhere.

# Usage
parallel_processing(M, filters, pairs_index, dataset, weights, weak_classifier)


# %%
# print("Best Filter:", best_filter)
# print("Best Threshold:", best_threshold)
# print("Min error", min_error)
# print('Confidence', confidence)

# %%



