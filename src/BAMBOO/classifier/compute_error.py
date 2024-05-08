from . import classifier, func
from utils import logger

def get_error(weigth: float, prediction: int, ground_truth: int) -> float:
    error = weigth * func.delta(prediction, ground_truth)

    logger.log.debug(f"Weigth {weigth}, Prediction {prediction}, Ground Truth {ground_truth}")

    return error


def compute_error(args):
    pair, pairs_index, threshold, filter, dataset, weak_classifier, weights = args
    prediction = classifier.weak_classifier(
        tuple(dataset.iloc[pairs_index.iloc[pair, 0:2], 0]),
        threshold,
        filter,
    )
    return get_error(weights[pair], prediction, pairs_index.iloc[pair, 2])

def parallel_compute_errors(pair_data):
    pair, pairs_index, thresholds, filter, dataset, weak_classifier, weights = pair_data
    errors = []
    for threshold in thresholds:
        error = compute_error((pair, pairs_index, threshold, filter, dataset, weak_classifier, weights))
        errors.append(error)
    return errors