<br />
<div align="center">
  <a href="https://github.com/GiovanniBaccichet/COMPACT">
    <img src="../images/compact_logo.png" alt="Logo" width="400">
  </a>

<h3 align="center">Notebooks</h3>

  <p align="center">
    Compressed features and representations for network traffic analysis in centralized and edge internet architectures.
    <br />
    <a href="https://compact-prin.github.io/"><strong>Website »</strong></a>
    <br />
    <br />
    <a href="https://antlab.deib.polimi.it/">ANT Lab - PoliMI</a>
    ·
    <a href="https://github.com/GiovanniBaccichet/COMPACT/issues">Report Bug</a>
    ·
    <a href="https://github.com/GiovanniBaccichet/COMPACT/issues">Request Feature</a>
  </p>
</div>

</details>

## Data Sources

The series of notebooks deal mainly with 3 different sources of data: the one coming from [UIJ Dataset](https://zenodo.org/records/7801798), that are useful to understand the trends wrt Information Elements in a very large and modern (but unlabelled) dataset; the one coming from our extended version of the [Pintor et al. dataset](https://www.sciencedirect.com/science/article/abs/pii/S1389128622000196), extracted following what the authors did in the paper; the last, but most interesting one is coming from the same extended dataset, but using a different approach in data extraction: we implemented a custom dissector to extract each sub-field of the Information Elements.

> This data extraction technique allows us to have the maximum granularity possible with respect to the actual bits of data used to discriminate between devices, in the context of MAC Address de-randomization techniques.

## Naming Scheme

The difference in the naming scheme we adopted, between the two data extraction techniques, with respect to the extended dataset is:
- **extracted**: technique that follows the above cited paper
- **dissected**: technique we introduces, which provides more granularity

When `raw` is appended to the name of a file, it means that `NaN` values are preserved. On the other hand, `fillna("-1", inplace=True) is used.

## Folder Structure

It is useful to have a general view of the files contained in this folder. The tree view below can help in this regard. The folder has different children, which have a dedicated section in this readme file. The order of the sections reflects as much as possible the reasoning we did when creating them, as well as the proper order of execution of the notebooks. This is necessary for reproducing our results, since many notebooks rely on the outputs of others, to be used as inputs.

```
.
├── config.ini
├── data_encoding
│   ├── IE_embeddings.ipynb
│   ├── IE_one-hot_encoding.ipynb
│   └── IE_sum_encoding.ipynb
├── data_exploration_cleaning
│   ├── data_balancing.ipynb
│   ├── data_cleaning_SSID_length.ipynb
│   ├── data_exploration_field_len.ipynb
│   ├── data_exploration_IE_useless_bits.ipynb
│   ├── data_exploration_temporal.ipynb
│   ├── data_pre-processing.ipynb
│   ├── data_visualization_correlation.ipynb
│   ├── data_visualization_statistics.ipynb
│   ├── dissected
│   │   ├── dissected_balancing.ipynb
│   │   ├── dissected_burst_view.ipynb
│   │   ├── dissected_heatmap_all_features.ipynb
│   │   ├── dissected_pre-processing.ipynb
│   │   ├── dissected_row_image.ipynb
│   │   └── dissected_visualization_statistics.ipynb
│   └── uji_dataset
│       ├── uji_cleaning.ipynb
│       ├── uji_non_random_filter.ipynb
│       └── uji_visualization_statistics.ipynb
├── data_testing_subsets
│   └── data_subset_generation.ipynb
├── models_feature_engineering
│   ├── feature_selection_forward_RF_std.ipynb
│   ├── feature_selection_RF.ipynb
│   ├── feature_selection_RF_std_dissected.ipynb
│   ├── feature_selection_SKB_std_dissected.ipynb
│   └── feature_statistcs_dissected.ipynb
├── models_train_evaluate
│   ├── DBSCAN_burst_dissected_selected.ipynb
│   ├── DBSCAN_multi_cardinality.ipynb
│   ├── DBSCAN_std_burst_dissected.ipynb
│   └── DBSCAN_SUM_encoding_Pintor.ipynb
├── pairwise_boosting
│   ├── bamboo_data_playground.ipynb
│   ├── bamboo.ipynb
│   └── ground_truth_generation.ipynb
├── README.md
├── scripts
│   ├── encodingHelper.py
│   ├── __init__.py
│   ├── plotHelper
│   │   ├── barPlots.py
│   │   ├── heatmaps.py
│   │   ├── __init__.py
│   │   ├── pieCharts.py
│   │   └── statisticsPlot.py
└── Template.ipynb
```

## data_exploration_cleaning

Data pre-processing and visualization, including cleaning and balancing data. The purpose of the notebooks contained in this folder is to get an idea of the data we are working with, including understanding the most interesting features (that must be confirmed during the feature selection process).

### data_pre-processing
> Input: all the `.CSV` files in `config["DEFAULT"]["extracted_path"]`

> Output: `data/interim/combined_df_raw.csv`, `data/interim/combined_df.csv`

This notebook merges the **extracted** files into a unique file.

### data_balancing

> Input: `combined_df_raw.csv`

> Output: `balanced_df_raw.csv`, `balanced_df.csv`, `encoded_LABEL_balanced_df.csv`

This notebook balances the labelled dataset with respect to the average number of rows per unique Label. It undersamples the input dataframe with a fixed random seed for reproducibility.

### data_cleaning_SSID_length

> Input: `balanced_df_raw.csv`, `encoded_LABEL_balanced_df.csv`

> Output: `balanced_df_raw_no_ssid.csv`, `encoded_LABEL_balanced_df_length.csv`

This notebook drops the `SSID` column, subtracting the length of each row to the respective `Length` column. This is done to balanced data, as well as **label encoded** data. Label encoding is performed in another notebook.

### data_exploration and data_visualization

These notebooks, as the names suggest, are used for data exploration and visualization. We won't delve into each one of them, since they do not produce outputs that are used in other notebooks.

### 📁 dissected

#### dissected_pre-processing

> Input: all the `.CSV` files in `config["DEFAULT"]["dissected_path"]`

> Output: `data/interim/dissected/dissected_df_raw.csv`, `data/interim/dissected/dissected_df.csv`

#### dissected_burst_view

> Input: `interim/dissected/selected_dissected_df.csv`, `dissected/std_dissected_df_raw.csv`

> Output: `data/interim/dissected/selected_burst_dissected_df.csv` `/dissected/std_burst_dissected_df.csv`

This notebook takes as input the dataframes generated by different notebooks in `models_feature_engineering` and groups the rows on the `MAC Address`, dropping the devices that did not use MAC Address Randomization (i.e., the `Label` having only 1 row in the grouped dataframe).

#### dissected_balancing

> Input: `dissected/dissected_df_raw.csv`

> Output: `dissected/balanced_dissected_df_raw.csv`, `dissected/balanced_dissected_df.csv`

This notebook balances the rows of the dissected data, based on the average number of rows per Label. Rows are undersampled, with a fixed random seed, for reproducibility purposes.

#### dissected_heatmap_all_features

Data visualization for the `std_dissected_df_raw.csv`. This notebook creates a heatmap Label vs Feature for each feature in the file.

### 📁 uji_dataset

Similarly tho what done for the **extracted** data. Won't comment on each notebook since this analysis is not used in the other notebooks (feature selection, training, etc.) due to the fact that it is not a labelled dataset, and for that reason we cannot get precise statistics on the classification / clustering performance.

## data_testing_subsets

### data_subset_generation

> Output: `/CSV/subset_combinations/unique_combinations.csv`

Generate subsets of the dataset of increasing cardinality. In total we generated 10 subset per cardinality, where possible.

