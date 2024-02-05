import pandas as pd
from sklearn import preprocessing

def label_encode_with_exception(column, removeValue = '-1'):
    label_encoder =preprocessing.LabelEncoder()
    # Create a temporary copy of the column
    temp_column = column.copy()
    # Identify rows where the value is -1
    mask = column != removeValue
    # Apply label encoding only to other rows
    temp_column[mask] = label_encoder.fit_transform(column[mask])
    # Return the transformed temp column
    return temp_column