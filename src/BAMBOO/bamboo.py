#!/usr/bin/env python

import argparse
import csv
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from configparser import ConfigParser

import numpy as np
import pandas as pd
from classifier import classifier, compute_error, threshold_gen
from rich import traceback
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeRemainingColumn
from utils import logger, title

traceback.install()

console = Console()

GRANULARITY = 32

MAX_WORKERS = 32


def main():
    csv_file = "best_configs.csv"

    title.print_title()

    parser = argparse.ArgumentParser(description="AsymMetric pairwise BOOsting")
    parser.add_argument("-M", type=int, help="number of iterations")
    parser.add_argument("-F", type=int, help="number of filters to use")
    parser.add_argument(
        "-X", type=int, help="number of head rows to use from the dataset"
    )
    parser.add_argument("-d", action="store_true", help="use debug dataset")
    parser.add_argument(
        "-rb", action="store_true", help="remove best filters at each iteration"
    )
    args = parser.parse_args()

    if args.M is None:
        console.print(
            Panel("[!] Argument M is missing! Setting it to 1.", style="bold red"),
            style="bold red",
        )
        args.M = 1

    if args.F is None:
        console.print(
            Panel("[!] Argument F is missing! Setting it to 16.", style="bold red"),
            style="bold red",
        )
        args.F = 16

    # Define custom columns for the progress bar
    custom_columns = [
        BarColumn(bar_width=None),
        " ",  # Spacer
        TextColumn("[progress.description]{task.description}"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        " ",  # Spacer
        TextColumn("[progress.remaining]{task.completed}/{task.total}"),
        TimeRemainingColumn(),
    ]

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
        console.print(
            Panel("[!] Using debug dataset.", style="bold green"),
            style="bold green",
        )
        pairs_df = pd.read_csv(config["DEFAULT"]["df_debug_pairs_path"], index_col=0)
    else:
        pairs_df = pd.read_csv(config["DEFAULT"]["df_pairs_path"], index_col=0)

    # Import bitmask filters

    filters_df = pd.read_csv(config["DEFAULT"]["filters_path"], index_col=0)

    if args.F == 0:
        n_filters = filters_df.shape[0]

    filters_df = filters_df.head(n_filters).reset_index()

    filters_bitmask = filters_df["Bitmask"]

    # Generation thresholds for each bitmask
    # threshold_list = threshold_gen.generate_thresholds(filters_bitmask)

    threshold_list = threshold_gen.generate_thresholds_df(filters_bitmask, GRANULARITY)

    # Remove the existing file if it exists
    if os.path.exists(csv_file):
        console.print(
            Panel("[!] Deleted previous best configs.", style="bold yellow"),
            style="bold yellow",
        )
        os.remove(csv_file)

    # Renaming algorithm input for better understanding
    dataset = strings_df
    if args.X:
        pairs_index = pairs_df.head(args.X)
    else:
        pairs_index = pairs_df
    filters = threshold_list

    # Generating init weights
    weights = np.ones(len(pairs_index)) / len(pairs_index)

    # Create a Rich progress context
    with Progress(*custom_columns) as progress:
        # Create a task for the outer loop
        iteration_task = progress.add_task(
            "[cyan]Going through iterations...", total=n_iterations
        )

        for i in range(n_iterations):  # iterations
            total_inner_iterations = sum(
                len(row["thresholds"]) for _, row in filters.iterrows()
            )

            # Create a task for the inner loop
            filters_task = progress.add_task(
                "[green]Processing filters...", total=total_inner_iterations
            )

            errors = {}

            with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = []

                for index, row in filters.iterrows():  # for each filter
                    filter = row["filters"]
                    thresholds = row["thresholds"]

                    errors = {}

                    for threshold in thresholds:  # for each threshold
                        futures.append(
                            executor.submit(
                                compute_error.pairs_error,
                                pairs_index,
                                dataset,
                                threshold,
                                filter,
                                weights,
                            )
                        )
                        progress.update(filters_task, advance=1)

                    for future in as_completed(futures):
                        try:
                            key, error = future.result()
                            errors[key] = error
                        except Exception as e:
                            logger.log.critical(f"An error occurred: {e}")

            # Find the minimum error
            min_error = min(errors.values())

            # Sorting the list by error, number of '1's in filter, and threshold
            sorted_error_list = sorted(
                errors.items(), key=lambda x: (x[1], x[0].count("1"), x[0][1])
            )  # sorting criteria: primary key is x[2] (error), then the filter length, at the end the threshold

            best_filter, best_threshold = sorted_error_list[0][0]
            min_error = sorted_error_list[0][1]

            # Delete the row with the best_threshold
            filters = filters[filters["filters"] != best_filter]

            min_error, confidence = compute_error.get_confidence(
                errors, best_filter, best_threshold
            )

            best_configs = [best_filter, best_threshold, min_error, confidence]

            logger.print_best_config(best_configs)

            # Asymmetric weight update + normalization
            weights = classifier.weight_update(
                pairs_index, dataset, weights, best_filter, best_threshold, confidence
            )

            # Opening the CSV file in append mode
            # with open(csv_file, "a", newline="") as file:
            #     writer = csv.writer(file)
            #     writer.writerow(best_configs)

            # Update the process at each iteration
            progress.update(iteration_task, advance=1)


if __name__ == "__main__":
    main()
