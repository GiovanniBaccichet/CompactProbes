<br />
<div align="center">
  <a href="https://github.com/GiovanniBaccichet/COMPACT">
    <img src="images/compact_logo.png" alt="Logo" width="370">
  </a>

<h3 align="center">COMPACT</h3>

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



<!-- ABOUT THE PROJECT -->
## About The Project

Reducing complexity and costs of network traffic analysis Network traffic analysis is a critical tool used by network operators for monitoring, managing, and ensuring the security of networks at different scales. Traditional network traffic analysis involves capturing network data and can demand extensive storage and computational resources, resulting in high management and operational costs. The COMPACT project aims to revolutionize traffic analysis by reducing resource complexity and costs associated with it.

- **Shift to Feature-Based Analysis**: COMPACT promotes a shift from conventional packet-based traffic representation to a feature-based approach. Statistical features are extracted from captured data and employed in machine learning algorithms.

- **Native Feature-Based Systems**: COMPACT explores the creation of native feature-based traffic analysis systems that sidestep the traditional packet-based representation. This shift reduces storage costs while maintaining analysis accuracy.

- **Lossy Compression Techniques**: A key innovation pursued by COMPACT is the development of lossy compression techniques tailored to network traffic features. These techniques significantly cut storage costs without sacrificing analysis accuracy.

- **Rate-Accuracy Tradeoff Exploration**: The project includes the development of models to analyze the trade-off between compression rates and analysis accuracy. This helps identify critical traffic features for specific analysis tasks.

The methodologies developed in the COMPACT project will be tested in various network scenarios. These scenarios encompass central traffic analysis in backbone networks, examination of IoT traffic in home networks, and various traffic analysis tasks across different network elements and traffic rates.

<!-- REPOSITORY STRUCTURE -->
## Repository Structure

Repository is organized according to the [Cookiecutter Data Science](https://github.com/drivendata/cookiecutter-data-science) structure. In the box below, we add some notes about each notebook, script and folder as a sort of Table of Contents.

```
.
├── README.md
├── data
│   ├── extracted                                        ← Data extracted from raw, using /src/data_extraction
│   ├── interim                                          ← Intermediate data that has been transformed
│   ├── processed                                        ← The final, canonical data sets for modeling
│   └── raw                                              ← The original, immutable data dump in .PCAP format
│
├── images
├── models                                               ← Trained and serialized models
├── notebooks
│   ├── Template.ipynb
│   ├── config.ini                                       ← Configuration files for /notebooks, containing paths
│   ├── data_encoding                                    ← Data encodings and embeddings tests and comparisons
│   │   ├── IE_embeddings.ipynb
│   │   ├── IE_one-hot_encoding.ipynb
│   │   └── IE_sum_encoding.ipynb
│   ├── data_exploration_cleaning                        ← Data pre-processing and visualization from /data/raw to /data/interim
│   │   ├── data_balancing.ipynb                         ← Balancing Baccichet + Pintor dataset. Outputs: balanced_df_raw, encoded_LABEL_balanced_df
│   │   ├── data_cleaning_SSID_length.ipynb
│   │   ├── data_exploration_temporal.ipynb              ← Experimenting with time-related features: IBAT, FSCT
│   │   ├── data_pre-processing.ipynb                    ← Filling combined_raw dataset NaN with -1. Output: combined_df
│   │   ├── data_visualization_correlation.ipynb         ← Analysis of label encoded features
│   │   ├── data_visualization_statistics.ipynb          ← Analysis of label encoded features
│   │   └── uji_dataset                                  ← Notebooks for the unlabelled UJI Dataset (used for generalization)
│   │       └── data_visualization_statistics_uji.ipynb
│   ├── data_testing_subsets
│   │   └── data_subset_generation.ipynb                 ← Generating randomized subsets for testing. Output: /reports/CSV/subset_combinations/unique_combinations.csv
│   ├── models_feature_engineering
│   │   └── feature_selection_RF.ipynb
│   ├── models_train_evaluate
│   └── scripts
│       ├── __init__.py
│       ├── encodingHelper.py
│       └── plotHelper
├── reports
└── src                                                  ← Source code for use in this project
    └── data_extraction                                  ← Data extraction tool from /data/raw to /data/extracted
        ├── config.ini                                   ← Configuration files for /data_extraction, containing paths
        └── data_extraction.py
```