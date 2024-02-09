import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt


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
