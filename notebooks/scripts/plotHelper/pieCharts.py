import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt


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
