import math

import numpy as np
import pandas as pd

from . import filters


def weak_classifier(
    string_pair_df: pd.DataFrame, threshold: int, filter_str: str
) -> list:
    filter = filters.filter_to_vector(filter_str)

    items_1 = np.array(string_pair_df["Item 1"].tolist())
    items_2 = np.array(string_pair_df["Item 2"].tolist())

    M_xa = np.multiply(items_1.astype(int), filter)
    M_xb = np.multiply(items_2.astype(int), filter)

    M_f_xa = np.sum(M_xa, axis=1)
    M_f_xb = np.sum(M_xb, axis=1)

    M_f_xa_t = M_f_xa - threshold * np.ones(len(M_f_xa))
    M_f_xb_t = M_f_xb - threshold * np.ones(len(M_f_xb))

    # Calculate element-wise product
    product = M_f_xa_t * M_f_xb_t

    # Generate array with +1 where elements match and -1 otherwise
    result_array = np.where(product == 1, 1, -1)

    # predictions = np.sign(M_f_xa_t * M_f_xb_t)

    predictions = result_array.tolist() 

    return predictions


def normalize_weight(ground_truth: list, updated_weights: list) -> list:
    mask = ground_truth == 1

    sum_values_to_normalize = np.sum(updated_weights[mask])

    updated_weights[mask] = updated_weights[mask] / sum_values_to_normalize

    return updated_weights


def weight_update(
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

    predictions = weak_classifier(df, best_threshold, best_filter)

    prediction_matrix = np.array(predictions).reshape(-1, 1)

    prediction_matrix[prediction_matrix == 1] = 0
    prediction_matrix[prediction_matrix != 1] = 1

    confidence_weight_matrix = (math.exp(confidence) * np.ones(len(weights))).reshape(
        -1, 1
    )

    updatedWeights = np.multiply(
        np.multiply(ground_truth_matrix, prediction_matrix), confidence_weight_matrix
    ) + np.multiply((~ground_truth_matrix.astype(bool)), weights.reshape(-1, 1))

    normalized_updated_weights = normalize_weight(ground_truth, updatedWeights)

    return normalized_updated_weights.flatten()
