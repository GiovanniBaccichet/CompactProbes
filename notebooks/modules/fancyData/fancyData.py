import os
import pandas as pd

def load_and_concat_csv(binary_path):
    """
    Traverse a directory to find CSV files, load them into DataFrames, and concatenate them.

    Args:
        binary_path (str): The root directory path to traverse for CSV files.

    Returns:
        pd.DataFrame: A single DataFrame containing all concatenated CSV data.
    """
    # Initialize an empty dictionary to store DataFrames
    dataframes = {}

    # Traverse the directory structure
    for root, dirs, files in os.walk(binary_path):
        for file in files:
            if file.endswith(".csv"):
                # Construct the full file path
                file_path = os.path.join(root, file)

                # Read the CSV file into a DataFrame
                df_tmp = pd.read_csv(file_path, dtype=str)

                # Store the DataFrame in the dictionary with a unique key (e.g., file name)
                dataframes[file] = df_tmp

    # Concatenate all DataFrames into one
    return pd.concat(dataframes.values(), ignore_index=True)

def pad_columns(df, symbol='0', exclude=[],length=None):
    max_lengths = df.drop(columns=exclude).apply(lambda col: col.map(lambda x: len(str(x)))).max()
    for col in df.columns:
        if col not in exclude:
            max_length = length if length is not None else max_lengths[col]
            df[col] = df[col].fillna("").astype(str).str.ljust(max_length, symbol)
    return df