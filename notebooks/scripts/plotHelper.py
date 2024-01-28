import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd


def plot_label_distribution(df, column_name, log_scale=False):
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


def plot_heatmap(df, column1, column2, colormap="Blues"):
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
    plt.figure(figsize=(25, 15))
    sns.heatmap(crosstab, annot=True, fmt="d", cmap=colormap)

    # Add title and labels
    plt.title(f"Heatmap of {column1} vs {column2}")
    plt.xlabel(column2)
    plt.ylabel(column1)

    # Show the plot
    plt.show()

def plot_pie_chart(df, column_name):
    # Check if the column exists in the DataFrame
    if column_name not in df.columns:
        print(f"Column '{column_name}' not found in DataFrame.")
        return

    # Calculate the value counts and the percentage of each category
    data = df[column_name].value_counts()
    data_percentage = data / data.sum()

    # Group categories with less than 5% into an "Others" category
    other_categories = data_percentage[data_percentage < 0.05].index
    data['Others'] = data[other_categories].sum()
    data = data.drop(other_categories)
    data_percentage = data / data.sum()

    # Set the seaborn style
    sns.set(style="whitegrid")

    # Create a pie plot
    plt.figure(figsize=(10, 8))
    plt.pie(data, labels=data.index, autopct='%1.1f%%', startangle=140, colors=sns.color_palette("pastel"))
    plt.title(f'Pie Chart of {column_name}', fontsize=16)
    plt.show()
