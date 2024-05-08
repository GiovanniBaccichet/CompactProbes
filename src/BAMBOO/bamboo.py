from configparser import ConfigParser
import os
from rich.progress import Progress, BarColumn, TextColumn
from rich import traceback

from classifier import classifier, compute_error, threshold_gen

import pandas as pd

import numpy as np

import math

from utils import title

import argparse

import multiprocessing

from tqdm import tqdm

traceback.install()


def main():

    title.print_title()

    parser = argparse.ArgumentParser(description="AsymMetric pairwise BOOsting")
    parser.add_argument("-M", type=int, help="number of iterations")
    parser.add_argument("-F", type=int, help="number of filters to use")
    parser.add_argument("-X", type=int, help="number of head rows to use from the dataset")
    parser.add_argument("-d", action='store_true', help="use debug dataset")
    args = parser.parse_args()

    if args.M is None:
        print("[!] Argument M is missing! Setting it to 1.")
        args.M = 1

    if args.F is None:
        print("[!] Argument F is missing! Setting it to 16.")
        args.F = 16

    n_iterations = args.M
    n_filters = args.F

    # Import the config file
    config = ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "config.ini"))

    # Import concatenated columns dataframe

    strings_df = pd.read_csv(config["DEFAULT"]["df_strings_path"], index_col=0)
    strings_df = strings_df.rename(columns={strings_df.columns[0]: "Probes"})

    # Importing pairs_df w/ index and ground truth from strings_df

    if args.d:
        print('Enabled debug dataset')
        pairs_df = pd.read_csv(config["DEFAULT"]["df_debug_pairs_path"], index_col=0)
    else:
        pairs_df = pd.read_csv(config["DEFAULT"]["df_pairs_path"], index_col=0)

    # Import bitmask filters

    filters_df = pd.read_csv(config["DEFAULT"]["filters_path"], index_col=0)

    filters_df = filters_df.head(n_filters).reset_index()

    filters = filters_df["Bitmask"]

    # Generation thresholds for each bitmask
    threshold_list = threshold_gen.generate_thresholds(filters)

    # Removing the last threshold for each bitmask
    threshold_list = threshold_gen.remove_last_threshold(threshold_list)

    # Renaming algorithm input for better understanding
    dataset = strings_df
    if args.X:
        pairs_index = pairs_df.head(args.X)
    else:
        pairs_index = pairs_df
    filters = threshold_list

    # Generating init weights
    weights = np.ones(len(pairs_index)) / len(pairs_index)

    errors = {}

    for m in tqdm(range(n_iterations), desc="Iterations"):  # iterations
        best_filter = None
        best_threshold = None
        for filters_entry in tqdm(filters, desc="Filters"):  # for each filter
            filters_list, threshold_list = filters_entry

            for filter, thresholds in zip(
                filters_list, [threshold_list] * len(filters_list)
            ):
                for threshold in thresholds:  # for each threshold
                    error = 0
                    for pair in range(len(pairs_index)):  # for each pair
                        prediction = classifier.weak_classifier(
                            tuple(dataset.iloc[pairs_index.iloc[pair, 0:2], 0]),
                            threshold,
                            filter,
                        )
                        error += compute_error.get_error(
                            weights[pair], prediction, pairs_index.iloc[pair, 2]
                        )
                    errors[(filter, threshold)] = error
        best_filter, best_threshold = min(errors, key=lambda k: abs(errors[k]))

        print("Best Filter:", best_filter)
        print("Best Threshold:", best_threshold)

        min_error = errors[(best_filter, best_threshold)]
        confidence = math.log(
            (1 - min_error) / min_error
        )  # confidence of the weak classifier
        print("Min error", min_error)
        print("Confidence:", confidence)

        # Asymmetric Weight Update
        for pair in range(len(pairs_index)):

            # print(
            #     dataset[pair][2],
            #     weak_classifier(dataset[pair][0:2], best_threshold, best_filter),
            # )

            if pairs_index.iloc[pair, 2] == +1:
                if (
                    classifier.weak_classifier(
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


if __name__ == "__main__":
    main()
