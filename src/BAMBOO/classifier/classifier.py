import math

import pandas as pd
from utils import logger

from . import filters, func


def weak_classifier(pair: tuple, threshold: int, filter: str) -> int:
    logger.log.debug(f"Pair {pair}\nThreshold {threshold}\nFilter {filter}")

    filtered1 = filters.sumFilter(filters.bitwise_and(pair[0], filter))
    filtered2 = filters.sumFilter(filters.bitwise_and(pair[1], filter))

    return func.sign((filtered1 - threshold) * (filtered2 - threshold))


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
        if pairs_index.iloc[p_index, 2] == +1:  # if the pair is a matching one
            if (
                weak_classifier(
                    tuple(dataset.iloc[pairs_index.iloc[p_index, 0:2], 0]),
                    best_threshold,
                    best_filter,
                )
                != +1
            ):  # if the prediction is wrong
                old_weight = weights[p_index]
                weights[p_index] = weights[p_index] * math.exp(confidence)
                logger.log.warning(
                    f"Weight updated @ {p_index}: {old_weight} -> {weights[p_index]}"
                )

    return weight_normalize(pairs_index, weights)
