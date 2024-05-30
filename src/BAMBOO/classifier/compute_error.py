import gc
import math

import numpy as np
import pandas as pd

from . import classifier


def get_confidence(errors: dict, best_filter: str, best_threshold: str) -> tuple:
    min_error = errors[(best_filter, best_threshold)]

    if min_error == 0:
        min_error = 10**-20

    confidence = math.log(
        (1 - min_error) / min_error
    )  # confidence of the weak classifier

    return min_error, confidence


def matrix_error(
    string_pair_df: pd.DataFrame,
    thresholds: list,
    filter: list,
    weights: list,
) -> float:
    for threshold in thresholds:
        error = 0

        predictions = classifier.weak_classifier(
            string_pair_df, threshold, filter
        )

        ground_truth = string_pair_df["Equality"].to_list()

        errors = np.not_equal(predictions, ground_truth).astype(int)

        error = sum(errors * weights)

        del (
            predictions,
            errors,
        )
        gc.collect()

    return (f"{filter}", threshold), error
