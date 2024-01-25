from configparser import ConfigParser
import os
from tqdm import tqdm

from netpress import PCAPextractor

from FileUtility import *


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

            # Set the file path for the PCAP file
            file_path = os.path.join(capture_path, filename)

            # Extract information from the PCAP file
            info = PCAPextractor.extract_pcap_info(file_path, label)

            if info:
                # Check if the output folder exists
                checkCreatePath(output_path)

                # Write the information to a CSV file
                header = [
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

                csv_writer(header, info, output_path, label)
