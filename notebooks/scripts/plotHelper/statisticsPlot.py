import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import math


def plot_boxplot(
    df: pd.DataFrame, group_column: str, value_column: str, log_scale=False
) -> None:
    # Check if the columns exist in the DataFrame
    if group_column not in df.columns or value_column not in df.columns:
        print(
            f"One or both columns '{group_column}' and '{value_column}' not found in DataFrame."
        )
        return

    # Set the seaborn style
    sns.set(style="whitegrid")

    # Create the boxplot
    plt.figure(figsize=(20, 12))
    ax = sns.boxplot(x=group_column, y=value_column, data=df)

    if log_scale:
        # Set the y-axis to logarithmic scale
        ax.set_yscale("log")

    # Set title and labels
    plt.title(f"Box Plot of {value_column} grouped by {group_column}")
    plt.xlabel(group_column)
    plt.ylabel(value_column)

    # Set the labels for the horizontal axis in vertical orientation
    ax.set_xticklabels(ax.get_xticklabels(), rotation=90)

    # Show the plot
    plt.show()


def plot_average_and_error(
    df: pd.DataFrame, group_column: str, value_column: str
) -> None:
    """
    Plots the average and standard deviation of a specified value for each group in a DataFrame.

    Args:
    df (pd.DataFrame): The DataFrame containing the data.
    group_column (str): The name of the column to group the data by.
    value_column (str): The name of the column for which to calculate the average and standard deviation.
    """
    # Check if the columns exist in the DataFrame
    if group_column not in df.columns or value_column not in df.columns:
        print(
            f"One or both columns '{group_column}' and '{value_column}' not found in DataFrame."
        )
        return

    # Set the figure size
    plt.figure(figsize=(15, 10))

    sns.set(style="whitegrid")

    # Calculate the average and standard deviation per group
    average = df.groupby(group_column)[value_column].mean()
    error = df.groupby(group_column)[value_column].std()

    # Plot the average and error per group
    plt.errorbar(average.index, average, yerr=error, fmt="o")
    plt.xlabel(group_column)
    plt.ylabel(f"Average {value_column}")
    plt.title(f"Average {value_column} and Error per {group_column}")
    plt.xticks(rotation=90)  # Rotate labels if they are too long
    plt.show()
