def sign(number: int) -> int:
    if number < 0:
        return -1
    elif number >= 0:
        return 1
    
def delta(prediction: int, ground_truth: int) -> int:
    if prediction != ground_truth:
        return 1
    else:
        return 0