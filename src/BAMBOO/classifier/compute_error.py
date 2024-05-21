import math

import pandas as pd
from rich.progress import Progress
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
    # progress: Progress,
    # task,
) -> float:
    error = 0
    for pair in range(len(pairs_index)):
        prediction = classifier.weak_classifier(
            tuple(dataset.iloc[pairs_index.iloc[pair, 0:2], 0]),
            threshold,
            selected_filter,
        )
        error += get_error(weights[pair], prediction, pairs_index.iloc[pair, 2])
        # progress.update(task, advance=1)
    # return error
    return (selected_filter, threshold), error
