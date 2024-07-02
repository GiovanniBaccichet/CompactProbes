#!/usr/bin/env python

import argparse
import gc
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from configparser import ConfigParser

import numpy as np
import pandas as pd
from classifier import classifier, compute_error, threshold_gen
from classifier import filters as filter_utility
from rich import traceback
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress

import utils as utils

traceback.install()

console = Console()


def main():
    utils.title.print_title()

    parser = argparse.ArgumentParser(description="AsymMetric pairwise BOOsting")

    args = utils.argsUtil.argsHandler(parser, console)

    n_iterations = args.M
    n_filters = args.F

    # Define custom columns for the progress bar
    custom_columns = utils.progressBarUtil.generateColumns()

    config = ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "config.ini"))

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

    filters_df = pd.read_csv(config["DEFAULT"]["advanced_filters_path"], index_col=0)

    pairs_df.drop_duplicates(inplace=True)
    pairs_df.reset_index(drop=True, inplace=True)

    # Check if user selected a number of filters
    if args.F == 0:
        n_filters = filters_df.shape[0]

    # Slice filters
    filters_df = filters_df.head(n_filters).reset_index()

    filters_bitmask = filters_df["Bitmask"]

    # Generate thresholds for each filter, depending on its size
    filters = threshold_gen.generate_thresholds_df(filters_bitmask)

    if args.X:
        pairs_index = pairs_df.head(args.X)
    else:
        pairs_index = pairs_df

    # Generating init weights
    weights = np.ones(len(pairs_index)) / len(pairs_index)

    string_pair_df = utils.matrixUtil.generateStringPairDf(pairs_index, dataset)

    del (dataset, strings_df, filters_bitmask, pairs_df, pairs_index, filters_df)

    gc.collect()

    n_processes = int(config["MULTI-PROCESSING"]["max_workers"])

    chunk_errors = {}

    # Create a Rich progress context
    with Progress(*custom_columns) as progress:
        # Create a task for the outer loop
        iteration_task = progress.add_task(
            "[cyan]Going through iterations...", total=n_iterations
        )

        for _ in range(n_iterations):  # iterations
            # Create a task for the inner loop
            filters_task = progress.add_task(
                "[green]Processing filters...", total=n_filters
            )

            chunked_indices = np.array_split(filters.index, n_processes)

            with ProcessPoolExecutor(max_workers=n_processes) as executor:
                futures = []
                chunk = []

                errors_dictionary = {}
                best_filter = None
                best_threshold = None

                for chunk_index in chunked_indices:
                    chunk = filters.loc[chunk_index]
                    futures.append(
                        executor.submit(
                            filter_utility.process_filters_chunk,
                            chunk,
                            string_pair_df,
                            weights,
                        )
                    )

                for future in as_completed(futures):
                    try:
                        result = future.result()
                        chunk_errors.update(result)  # Collect errors from each future

                        progress.update(filters_task, advance=len(chunk_errors))

                    except Exception as e:
                        utils.logger.log.critical(f"An error occurred: {e}")
                        raise e

            errors_dictionary.update(chunk_errors)

            sorted_error_list = sorted(
                errors_dictionary.items(),
                key=lambda x: (
                    x[1],  # primary key -> error
                    filter_utility.calculate_filter_width(
                        x[0]
                    ),  # secondary key -> filter length
                    x[0][1],  # tertiary key -> threshold
                ),
            )

            best_filter, best_threshold = sorted_error_list[0][0]
            min_error = sorted_error_list[0][1]

            # Delete the row with the best_filter
            filters = filters[filters["filters"] != best_filter]

            n_filters -= 1

            min_error, confidence = compute_error.get_confidence(
                errors_dictionary, best_filter, best_threshold
            )

            best_configs = [best_filter, best_threshold, min_error, confidence]

            utils.logger.print_best_config(best_configs)

            # Asymmetric weight update + normalization
            weights = classifier.weight_update(
                string_pair_df, weights, best_filter, best_threshold, confidence
            )

            del (
                sorted_error_list,
                errors_dictionary,
                best_filter,
                best_threshold,
                min_error,
                confidence,
            )

            gc.collect()

            progress.update(iteration_task, advance=1)


if __name__ == "__main__":
    main()
