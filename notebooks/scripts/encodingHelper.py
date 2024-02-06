import pandas as pd
from sklearn import preprocessing


def label_encode_with_exception(column, removeValue="-1"):
    label_encoder = preprocessing.LabelEncoder()
    # Create a temporary copy of the column
    temp_column = column.copy()
    # Identify rows where the value is -1
    mask = column != removeValue
    # Apply label encoding only to other rows
    temp_column[mask] = label_encoder.fit_transform(column[mask])
    # Return the transformed temp column
    return temp_column


def check_collisions(
    df: pd.DataFrame, column: str, encoded_column=None, label_column="Label"
) -> None:
    if not encoded_column:
        encoded_column = column + " SUM"

    # Group by the sum column and get unique values in the collision column
    collisions = df.groupby(encoded_column)[column].unique()

    printed = False
    for k, v in collisions.items():
        if len(v) > 1:
            if not printed:
                printed = True
            print(k, ":", end=" ")
            for x in v:
                print("\t", x, df[df[column] == x][label_column].unique())
            print()

    if not printed:
        print("No collision detected")
