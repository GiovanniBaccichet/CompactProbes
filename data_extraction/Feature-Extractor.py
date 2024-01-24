import os
import csv
from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Elt

# Path to the Captures folder
captures_folder = "/Users/bacci/Library/CloudStorage/SynologyDrive-giovanni/Research 🌱/ProbeLink/Repo/Feature-Extraction/Captures/Pintor"


# Create a function to extract information from a PCAP file
def extract_pcap_info(file_path):
    try:
        # Read the PCAP file using Scapy
        packets = rdpcap(file_path)

        output_data = []

        for packet in packets:
            timestamp = packet.time
            mac_address = packet.addr2
            channel = int((packet.Channel - 2407) / 5)

            try:
                ds_channel = packet[Dot11Elt][3].channel
            except:
                ds_channel = "0"

            try:
                htcapabilities = sum(int(char, 16) for char in packet.getlayer(Dot11Elt, ID=45).info.hex())
            except:
                htcapabilities = "0"

            try:
                extended_capabilities = sum(int(char, 16) for char in packet.getlayer(Dot11Elt, ID=127).info.hex())
            except:
                extended_capabilities = "0"

            try:
                vendor_specific_tags = sum(int(char, 16) for char in packet.getlayer(Dot11Elt, ID=221).info.hex())
            except:
                vendor_specific_tags = "0"

            for elt in packet.getlayer(Dot11Elt):
                if elt.ID == 45:
                    htcapabilities = sum(elt.payload.getlayer(Dot11Elt))
                elif elt.ID == 127:
                    extended_capabilities = sum(elt.payload.getlayer(Dot11Elt))

                if elt.ID == 221:
                    vendor_specific_tags = sum(elt.payload.getlayer(Dot11Elt))

            output_data.append(
                [
                    timestamp,
                    mac_address,
                    channel,
                    ds_channel,
                    htcapabilities,
                    extended_capabilities,
                    vendor_specific_tags,
                    label,
                ]
            )

        return output_data
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        return None


# Create a CSV file for each PCAP file in the Captures folder
for filename in os.listdir(captures_folder):
    if filename.endswith(".pcap"):
        label = os.path.splitext(filename)[0]
        file_path = os.path.join(captures_folder, filename)
        output_file = captures_folder+f"/CSV/{label}.csv"

        info = extract_pcap_info(file_path)
        if info:
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
                        "Label",
                    ]
                )
                csv_writer.writerows(info)

            print(f"Extracted information from {file_path} and saved to {output_file}")
