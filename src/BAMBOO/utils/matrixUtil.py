import numpy as np
import pandas as pd
    
def convertColumntoArray(df: pd.DataFrame, column_name: str) -> np.array:
    return np.array([list(bstr) for bstr in df[column_name]])

def generateStringPairDf(pairs_df: pd.DataFrame, dataset: pd.DataFrame) -> pd.DataFrame:
    # Convert the Probes column to a numpy array
    dataset_array = convertColumntoArray(dataset, "Probes")

    # Import the Probes into the pairs_df dataframe
    pairs_df["Item 1"] = pairs_df["Item 1"].apply(lambda index: dataset_array[index])
    pairs_df["Item 2"] = pairs_df["Item 2"].apply(lambda index: dataset_array[index])

    return pairs_df