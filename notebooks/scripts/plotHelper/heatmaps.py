import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt


def plot_heatmap(
    df: pd.DataFrame, column1: str, column2: str, colormap="Blues"
) -> None:
    """
    Creates a heatmap based on the frequency of occurrences between two categorical columns.

    :param df: pandas DataFrame containing the data.
    :param column1: String, name of the first column.
    :param column2: String, name of the second column.
    :param colormap: String, the colormap to be used for the heatmap.
    """
    # Compute a contingency table / cross-tabulation
    crosstab = pd.crosstab(df[column1], df[column2])

    # Create the heatmap
    sns.set(style="whitegrid", font_scale=1)
    plt.figure(figsize=(25, 15))
    sns.heatmap(crosstab, annot=True, fmt="d", cmap=colormap)

    # Add title and labels
    plt.title(f"Heatmap of {column1} vs {column2}")
    plt.xlabel(column2)
    plt.ylabel(column1)

    # Show the plot
    plt.show()


def plot_correlation_matrix(df: pd.DataFrame) -> None:
    """
    Plots the correlation matrix with annotations for a given DataFrame.

    Args:
    df (pandas.DataFrame): The DataFrame for which the correlation matrix will be plotted.
    """
    # Compute the correlation matrix for numerical columns
    corr = df.select_dtypes(["number"]).corr()

    # Set up the matplotlib figure
    f, ax = plt.subplots(figsize=(10, 10))

    # Draw the heatmap with the mask and correct aspect ratio
    sns.heatmap(
        corr,
        annot=True,
        fmt=".2f",
        cmap="viridis",
        square=True,
        linewidths=0.5,
        cbar_kws={"shrink": 0.5},
        ax=ax,
    )

    # Set titles and labels
    plt.title("Correlation Matrix", fontsize=16)
    plt.xticks(fontsize=14, rotation=90)
    plt.yticks(fontsize=14, rotation=0)

    # Show the plot
    plt.show()
