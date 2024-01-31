import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import math


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


def plot_pie_chart(df: pd.DataFrame, column_name: str, other_percentage=0.05) -> None:
    # Check if the column exists in the DataFrame
    if column_name not in df.columns:
        print(f"Column '{column_name}' not found in DataFrame.")
        return

    # Calculate the value counts and the percentage of each category
    data = df[column_name].value_counts()
    data_percentage = data / data.sum()

    # Group categories with less than other_percentage into an "Others" category
    other_categories = data_percentage[data_percentage < other_percentage].index
    data["Others"] = data[other_categories].sum()
    data = data.drop(other_categories)
    data_percentage = data / data.sum()

    # Set the seaborn style
    sns.set(style="whitegrid")

    # Create a pie plot
    plt.figure(figsize=(10, 8))
    plt.pie(
        data,
        labels=data.index,
        autopct="%1.1f%%",
        startangle=140,
        wedgeprops=dict(width=0.3),
        colors=sns.color_palette("pastel"),
    )
    plt.title(f"Pie Chart of {column_name}", fontsize=16)
    plt.show()


def plot_multi_pie_charts(df: pd.DataFrame, col_label: str, col_data: str) -> None:
    # Set the aesthetic style of the plots
    sns.set(style="whitegrid", font_scale=0.8)

    # Identify unique labels in the first column
    labels = df[col_label].unique()

    # Determine the number of donut charts (subplots) needed
    n_labels = len(labels)
    n_cols = 3  # number of columns in the plot grid
    n_rows = (n_labels + n_cols - 1) // n_cols  # calculate rows needed

    # Create subplots
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(n_cols * 4, n_rows * 4))
    axes = axes.flatten() if n_labels > 1 else [axes]

    # Plot a donut chart for each label
    for i, label in enumerate(labels):
        # Create a subset of the DataFrame for the label
        subset = df[df[col_label] == label]
        # Count the occurrences of each category in the second column
        value_counts = subset[col_data].value_counts()
        # Plot
        axes[i].pie(
            value_counts,
            labels=value_counts.index,
            autopct="%1.1f%%",
            startangle=140,
            wedgeprops=dict(width=0.3),
            colors=sns.color_palette("pastel"),
        )  # Adjust the width here for the donut hole size
        axes[i].set_title(f"Label: {label}", fontsize=14)

    # Remove unused subplots
    for j in range(i + 1, n_cols * n_rows):
        if j < len(axes):
            fig.delaxes(axes[j])

    plt.tight_layout()
    plt.show()


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


def plot_fsct_bar_by_label(data):
    # Identify the unique labels
    labels = data["Label"].unique()

    # Identify FSCT columns
    fsct_columns = [col for col in data.columns if col.startswith("FSCT")]

    # Extract just the number part of the FSCT columns for x-axis labels
    fsct_numbers = [col.replace("FSCT-", "") for col in fsct_columns]

    # Determine the number of rows needed for a 3-column layout
    n_rows = math.ceil(len(labels) / 3)

    # Create a figure for the plots
    fig, axes = plt.subplots(nrows=n_rows, ncols=3, figsize=(15, 5 * n_rows))
    axes = axes.flatten()  # Flatten the axes array for easy iteration

    # Iterate over each label
    for i, label in enumerate(labels):
        # Filter the data for the current label
        label_data = data[data["Label"] == label]

        # Calculate mean FSCT values for the label
        mean_values = label_data[fsct_columns].mean()

        # Create a bar plot
        axes[i].bar(fsct_numbers, mean_values.values)
        axes[i].set_title(f"Average FSCT Values for Label: {label}")
        axes[i].set_xlabel("FSCT")
        axes[i].set_ylabel("Average Value")

        # Set y-axis to logarithmic scale
        axes[i].set_yscale("log")

    # Hide unused axes if the number of labels is not a multiple of 3
    for j in range(i + 1, len(axes)):
        axes[j].axis("off")

    plt.tight_layout()
    plt.show()
