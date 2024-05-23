#!/usr/bin/env python

import argparse
import csv
import gc
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from configparser import ConfigParser

import numpy as np
import pandas as pd
from classifier import classifier, compute_error, threshold_gen
from rich import traceback
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from utils import argsUtil, logger, matrixUtil, progressBarUtil, title

traceback.install()

console = Console()

GRANULARITY = 32

MAX_WORKERS = 4

CSV_FILE = "best_configs.csv"


def main():
    title.print_title()

    parser = argparse.ArgumentParser(description="AsymMetric pairwise BOOsting")

    args = argsUtil.argsHandler(parser, console)

    n_iterations = args.M
    n_filters = args.F

    # Define custom columns for the progress bar
    custom_columns = progressBarUtil.generateColumns()

    # Import the config file

    config = ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "config.ini"))

    # Import concatenated columns dataframe
    strings_df = pd.read_csv(config["DEFAULT"]["df_strings_path"], index_col=0)
    dataset = strings_df.rename(columns={strings_df.columns[0]: "Probes"})

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

    # Check if user selected a number of filters
    if args.F == 0:
        n_filters = filters_df.shape[0]

    # Slice filters
    filters_df = filters_df.head(n_filters).reset_index()

    filters_bitmask = filters_df["Bitmask"]

    # Generate thresholds for each filter, depending on its size
    filters = threshold_gen.generate_thresholds_df(filters_bitmask, GRANULARITY)

    filters["filters"] = filters["filters"].apply(threshold_gen.binary_to_range)

    # Remove the existing file if it exists
    if os.path.exists(CSV_FILE):
        console.print(
            Panel("[!] Deleted previous best configs.", style="bold yellow"),
            style="bold yellow",
        )
        os.remove(CSV_FILE)

    if args.X:
        pairs_index = pairs_df.head(args.X)
    else:
        pairs_index = pairs_df

    # Generating init weights
    weights = np.ones(len(pairs_index)) / len(pairs_index)

    string_pair_df = matrixUtil.generateStringPairDf(pairs_index, dataset)

    del (dataset, strings_df, filters_bitmask, pairs_df, pairs_index, filters_df)

    gc.collect()

    # Create a Rich progress context
    with Progress(*custom_columns) as progress:
        # Create a task for the outer loop
        iteration_task = progress.add_task(
            "[cyan]Going through iterations...", total=n_iterations
        )

        with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []

            for _ in range(n_iterations):  # iterations
                total_inner_iterations = args.F

                # Create a task for the inner loop
                filters_task = progress.add_task(
                    "[green]Processing filters...", total=total_inner_iterations
                )

                errors = {}

                for _, row in filters.iterrows():  # for each filter
                    filter = row["filters"]
                    thresholds = row["thresholds"]

                    errors = {}

                    futures.append(
                        executor.submit(
                            compute_error.matrix_error,
                            string_pair_df,
                            thresholds,
                            filter,
                            weights,
                        )
                    )

                for future in as_completed(futures):
                    try:
                        if (
                            progress.tasks[filters_task].completed
                            == total_inner_iterations
                        ):
                            progress.update(filters_task, completed=0)
                        key, error = future.result()
                        errors[key] = error
                        progress.update(filters_task, advance=1)
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
                # weights = classifier.weight_update(
                #     pairs_index,
                #     dataset,
                #     weights,
                #     best_filter,
                #     best_threshold,
                #     confidence,
                # )

                # Update the process at each iteration
                progress.update(iteration_task, advance=1)


if __name__ == "__main__":
    main()
