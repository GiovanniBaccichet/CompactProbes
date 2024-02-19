def fieldPadder(field: list, length: int) -> list:
    """
    Pads a list with None values to a specified length.

    Args:
    field (list): The list to pad.
    length (int): The length to pad the list to.

    Returns:
    list: The padded list.
    """
    if len(field) == length:
        return field
    elif len(field) > length:
        return field[:length]
    return field + [None] * (length - len(field))


def noneList(length: int) -> list:
    """
    Creates a list of None values of a specified length.

    Args:
    length (int): The length of the list.

    Returns:
    list: The list of None values.
    """
    return [None] * length
