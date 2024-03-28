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

This data extraction technique allows us to have the maximum granularity possible with respect to the 

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

## `data_exploration_cleaning`

Data pre-processing and visualization, including cleaning and balancing data. The purpose of the notebooks contained in this folder is to get an idea of the data we are working with, including understanding the most interesting features (that must be checked during the feature selection process).