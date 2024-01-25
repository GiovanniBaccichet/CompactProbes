from .logger import log

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Elt

from .IEextractor import *


# Create a function to extract information from a PCAP file
def extract_pcap_info(file_path: str, label: str) -> list:
    try:
        # Read the PCAP file using Scapy
        packets = rdpcap(file_path)

        output_data = []

        for packet in packets:
            # Timestamp
            timestamp = extractTimestamp(packet)

            # Source MAC address
            mac_address = extractMAC(packet)

            # Channel number
            channel = extractChannel(packet)

            # DS Parameter Set channel number
            ds_channel = extractDSChannel(packet)

            # HT Capabilities (HEX)
            htcapabilities = extractHTCapabilities(packet)

            # Extended Capabilities (HEX)
            extended_capabilities = extractExtendedCapabilities(packet)

            # Vendor Specific Tags (HEX)
            vendor_specific_tags = extractVendorSpecificTags(packet)

            # Additional features

            # SSID
            ssid = extractSSID(packet)

            # Supported Rates (HEX)
            supported_rates = extractSupportedRates(packet)

            # Extended Supported Rates (HEX)
            extended_supported_rates = extractExtendedSupportedRates(packet)

            # VHT Capabilities (HEX)
            vhtcapabilities = extractVHTCapabilities(packet)

            # HE Capabilities (HEX)
            hecapabilities = extractHECapabilities(packet)

            output_data.append(
                [
                    timestamp,
                    mac_address,
                    channel,
                    ds_channel,
                    htcapabilities,
                    extended_capabilities,
                    vendor_specific_tags,
                    ssid,
                    supported_rates,
                    extended_supported_rates,
                    vhtcapabilities,
                    hecapabilities,
                    label,
                ]
            )

        return output_data

    except Exception as e:
        log.critical(f"Error extracting information from {file_path}: {e}")
        return RuntimeError
