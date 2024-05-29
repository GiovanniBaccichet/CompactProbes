import math

import pandas as pd
from utils import logger

import numpy as np

from . import filters, func


def weak_classifier(pair: tuple, threshold: int, filter: str) -> int:
    logger.log.debug(f"Pair {pair}\nThreshold {threshold}\nFilter {filter}")

    filtered1 = filters.sumFilter(filters.bitwise_and(pair[0], filter))  # f(xa)
    filtered2 = filters.sumFilter(filters.bitwise_and(pair[1], filter))  # f(xb)

    return func.sign(
        (filtered1 - threshold) * (filtered2 - threshold)
    )  # sign((f(xa)-t)(f(xb)-t))


def weight_normalize(pairs_index: pd.DataFrame, weights: list) -> list:
    # Weight normalization
    matching_pairs = []

    for n_index in range(len(pairs_index)):
        if pairs_index.iloc[n_index, 2] == +1:
            matching_pairs.append(n_index)

    matching_pairs_weights = [weights[index] for index in matching_pairs]
    total_weight = sum(matching_pairs_weights)

    normalized_weights = [weight / total_weight for weight in matching_pairs_weights]

    for index, matching_pair in enumerate(matching_pairs):
        weights[matching_pair] = normalized_weights[index]

    return weights


def normalize_weight_matrix(ground_truth: list, updated_weights: list) -> list:
    mask = ground_truth == 1

    sum_values_to_normalize = np.sum(updated_weights[mask])

    updated_weights[mask] = updated_weights[mask] / sum_values_to_normalize

    return updated_weights


def weight_update(
    pairs_index: pd.DataFrame,
    dataset: pd.DataFrame,
    weights: list,
    best_filter: str,
    best_threshold: int,
    confidence: float,
) -> list:
    # Asymmetric Weight Update
    for p_index in range(len(pairs_index)):  # pair index for asymmetric weight update
        ground_truth = pairs_index.iloc[p_index, 2]
        prediction = weak_classifier(
            tuple(dataset.iloc[pairs_index.iloc[p_index, 0:2], 0]),
            best_threshold,
            best_filter,
        )
        if ground_truth == +1:  # if the pair is a matching one
            if prediction != +1:  # if the prediction is wrong
                old_weight = weights[p_index]
                weights[p_index] = weights[p_index] * math.exp(confidence)

                logger.log.warning(
                    f"Weight updated @ {p_index}: {old_weight} -> {weights[p_index]}"
                )

    return weight_normalize(pairs_index, weights)


def matrix_weight_update(
    df: pd.DataFrame,
    weights: list,
    best_filter: str,
    best_threshold: int,
    confidence: float,
) -> list:
    # Keep only 1s in the ground truth matrix
    ground_truth = df["Equality"].to_list()
    ground_truth_matrix = np.array(ground_truth).reshape(-1, 1)

    # Convert -1 to 0 for later matrix product
    ground_truth_matrix[ground_truth_matrix != 1] = 0

    # Creating predictions using best filter and best threshold
    items_1 = np.array(df["Item 1"].tolist())
    items_2 = np.array(df["Item 2"].tolist())

    filter_start, filter_end = best_filter.split(":")

    filter_start = int(filter_start)
    filter_end = int(filter_end)

    M_xa = items_1[:, filter_start:filter_end].astype(int)
    M_xb = items_2[:, filter_start:filter_end].astype(int)

    M_f_xa = np.sum(M_xa, axis=1)
    M_f_xb = np.sum(M_xb, axis=1)

    M_f_xa_t = M_f_xa - best_threshold * np.ones(len(M_f_xa))
    M_f_xb_t = M_f_xb - best_threshold * np.ones(len(M_f_xb))

    predictions = np.sign(M_f_xa_t * M_f_xb_t)

    prediction_matrix = np.array(predictions).reshape(-1, 1)

    prediction_matrix[prediction_matrix == 1] = 0
    prediction_matrix[prediction_matrix != 1] = 1

    confidence_weight_matrix = (math.exp(confidence) * np.ones(len(weights))).reshape(-1, 1)

    updatedWeights = np.multiply(np.multiply(ground_truth_matrix, prediction_matrix), confidence_weight_matrix) + np.multiply((~ground_truth_matrix.astype(bool)), weights.reshape(-1, 1))

    normalized_updated_weights = normalize_weight_matrix(ground_truth, updatedWeights)

    return normalized_updated_weights
