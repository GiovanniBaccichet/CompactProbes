from utils import logger
from . import func, filters


def weak_classifier(pair: tuple, threshold: int, filter: str) -> int:
    logger.log.debug(f"Pair {pair}\nThreshold {threshold}\nFilter {filter}")
    filtered1 = filters.sumFilter(filters.bitwise_and(pair[0], filter))
    filtered2 = filters.sumFilter(filters.bitwise_and(pair[1], filter))
    return func.sign((filtered1 - threshold) * (filtered2 - threshold))
