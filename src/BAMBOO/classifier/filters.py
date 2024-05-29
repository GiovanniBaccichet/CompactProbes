from utils import logger


def bitwise_and(bit_str1: str, bit_str2: str) -> str:
    logger.log.debug(f"Bit String 1: {bit_str1}\nBit String 2: {bit_str2}")

    # Convert bit strings to integers
    int1 = int(bit_str1, 2)
    int2 = int(bit_str2, 2)

    # Perform bitwise AND operation
    result = int1 & int2

    # Convert result back to binary string
    result_str = bin(result)[2:]  # [2:] to remove '0b' prefix

    # Return result
    return result_str.zfill(max(len(bit_str1), len(bit_str2)))


def sumFilter(bitwise_and: str) -> int:  # decimal - converted sum filter
    sum = 0
    a = 0
    for i in bitwise_and:
        sum += (2**a) * int(i, 2)
        a += 1
    return sum


def calculate_filter_width(filter: str) -> int:
    filter_start, filter_end = filter[0].split(":")
    width = int(filter_end) - int(filter_start)
    return width
