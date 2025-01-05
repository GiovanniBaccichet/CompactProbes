import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


def plot_label_distribution(
    df: pd.DataFrame, column_name: str, log_scale=False
) -> None:
    """
    Plots the distribution of values in the specified column of the DataFrame with an option for logarithmic scale.

    :param df: pandas DataFrame containing the data.
    :param column_name: String, name of the column for which to plot the distribution.
    :param log_scale: Boolean, if True, the y-axis will be in logarithmic scale.
    """
    # Set the aesthetic style of the plots
    sns.set(style="whitegrid")

    # Create the plot
    plt.figure(figsize=(10, 6))
    sns.countplot(x=column_name, data=df)

    # Set logarithmic scale if required
    if log_scale:
        plt.yscale("log")

    # Add plot title and labels
    plt.title(f"Distribution of {column_name}" + (" (Log Scale)" if log_scale else ""))
    plt.xlabel(column_name)
    plt.ylabel("Count (Log Scale)" if log_scale else "Count")

    # Rotate x-axis labels for better readability if necessary
    plt.xticks(rotation=90)

    # Show the plot
    plt.show()
