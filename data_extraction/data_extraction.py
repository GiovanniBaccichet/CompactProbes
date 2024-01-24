from configparser import ConfigParser
import os
from tqdm import tqdm
import csv

import threading

from netpress import PCAPextractor

# Import the config file
config = ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "config.ini"))

# For each capture dataset in the config file, extract each PCAP file
for i in tqdm(config.sections()):

    # Set dataset path and output path
    capture_path = config[i]["raw_path"]
    output_path = config[i]["output_path"]

    # Create a CSV file for each PCAP file in the Captures folder
    for filename in tqdm(os.listdir(capture_path)):
        if filename.endswith(".pcap"):

            # Set output file name to the same as the PCAP file
            label = os.path.splitext(filename)[0]
            file_path = os.path.join(capture_path, filename)
            output_file = output_path + f"{label}.csv"

            # Extract information from the PCAP file
            info = PCAPextractor.extract_pcap_info(file_path, label)

            if info:

                # Check if the output folder exists
                if not os.path.exists(output_path):
                    os.makedirs(output_path)

                # Write the information to a CSV file
                with open(output_file, "w", newline="") as csvfile:
                    csv_writer = csv.writer(csvfile)
                    csv_writer.writerow(
                        [
                            "Timestamp",
                            "MAC Address",
                            "Channel",
                            "DS Channel",
                            "HT Capabilities",
                            "Extended Capabilities",
                            "Vendor Specific Tags",
                            "SSID",
                            "Supported Rates",
                            "Extended Supported Rates",
                            "VHT Capabilities",
                            "HE Capabilities",
                            "Label",
                        ]
                    )
                    csv_writer.writerows(info)
