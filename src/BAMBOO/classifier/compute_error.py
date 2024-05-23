import gc
import math

import numpy as np
import pandas as pd
from utils import logger

from . import classifier, func


def get_error(weigth: float, prediction: int, ground_truth: int) -> float:
    error = weigth * func.delta(prediction, ground_truth)

    logger.log.debug(
        f"Weigth {weigth}, Prediction {prediction}, Ground Truth {ground_truth}"
    )

    return error


def get_confidence(errors: dict, best_filter: str, best_threshold: str) -> tuple:
    min_error = errors[(best_filter, best_threshold)]

    if min_error == 0:
        min_error = 10**-20

    confidence = math.log(
        (1 - min_error) / min_error
    )  # confidence of the weak classifier

    return min_error, confidence


def pairs_error(
    pairs_index: pd.DataFrame,
    dataset: pd.DataFrame,
    threshold: int,
    selected_filter: str,
    weights: list,
) -> float:
    error = 0
    for pair in range(len(pairs_index)):
        prediction = classifier.weak_classifier(
            tuple(dataset.iloc[pairs_index.iloc[pair, 0:2], 0]),
            threshold,
            selected_filter,
        )
        error += get_error(weights[pair], prediction, pairs_index.iloc[pair, 2])
    return (selected_filter, threshold), error


def matrix_error(
    string_pair_df: pd.DataFrame,
    thresholds: list,
    filter: list,
    weights: list,
) -> float:
    for threshold in thresholds:  # for each threshold
        error = 0

        filter_start = filter[0]
        filter_end = filter[1]

        items_1 = np.array(string_pair_df["Item 1"].tolist())
        items_2 = np.array(string_pair_df["Item 2"].tolist())

        M_xa = items_1[:, filter_start:filter_end].astype(int)
        M_xb = items_2[:, filter_start:filter_end].astype(int)

        M_f_xa = np.sum(M_xa, axis=1)
        M_f_xb = np.sum(M_xb, axis=1)

        M_f_xa_t = M_f_xa - threshold * np.ones(len(M_f_xa))
        M_f_xb_t = M_f_xb - threshold * np.ones(len(M_f_xb))

        predictions = np.sign(M_f_xa_t * M_f_xb_t)

        ground_truth = string_pair_df["Equality"].to_list()

        errors = np.not_equal(predictions, ground_truth).astype(int)

        error = sum(errors * weights)

        del (
            items_1,
            items_2,
            M_xa,
            M_xb,
            M_f_xa,
            M_f_xb,
            M_f_xa_t,
            M_f_xb_t,
            predictions,
        )
        gc.collect()

    return (f"{filter_start}:{filter_end}", threshold), error
