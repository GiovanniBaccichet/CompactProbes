from utils import logger
from . import func, filters

import pandas as pd

import math


def weak_classifier(pair: tuple, threshold: int, filter: str) -> int:
    logger.log.debug(f"Pair {pair}\nThreshold {threshold}\nFilter {filter}")
    filtered1 = filters.sumFilter(filters.bitwise_and(pair[0], filter))
    filtered2 = filters.sumFilter(filters.bitwise_and(pair[1], filter))
    return func.sign((filtered1 - threshold) * (filtered2 - threshold))


def weight_normalize(pairs_index: pd.DataFrame, weights: list) -> list:
    # Weight normalization
    for n_index in range(len(pairs_index)): # normalization index
        if pairs_index.iloc[n_index, 2] == +1:
            weights[n_index] = weights[n_index] / sum(
                weights[n_index]
                for pair in range(len(pairs_index))
                if pairs_index.iloc[pair, 2] == +1
            )
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

        if pairs_index.iloc[p_index, 2] == +1: # if the pair is a matching one
            if (
                weak_classifier(
                    tuple(dataset.iloc[pairs_index.iloc[p_index, 0:2], 0]),
                    best_threshold,
                    best_filter,
                )
                != pairs_index.iloc[p_index, 2]
            ): # if the prediction is wrong
                old_weight = weights[p_index]
                weights[p_index] = weights[p_index] * math.exp(confidence)
                logger.log.warning(f"Weight updated @ {p_index}: {old_weight} -> {weights[p_index]}")

    return weight_normalize(pairs_index, weights)
