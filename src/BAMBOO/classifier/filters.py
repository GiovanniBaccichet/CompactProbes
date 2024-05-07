def bitwise_and(bit_str1: str, bit_str2: str) -> str:
    # Convert bit strings to integers
    int1 = int(bit_str1, 2)
    int2 = int(bit_str2, 2)

    # Perform bitwise AND operation
    result = int1 & int2

    # Convert result back to binary string
    result_str = bin(result)[2:]  # [2:] to remove '0b' prefix

    # Return result
    return result_str.zfill(max(len(bit_str1), len(bit_str2)))

def sumFilter(bitwise_and: str) -> int:
    sum = 0
    for i in bitwise_and:
        sum += int(i)
    return sum