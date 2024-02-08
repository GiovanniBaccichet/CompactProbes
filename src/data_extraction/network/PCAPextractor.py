from utils import logger

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Elt

from network import IEextractor


# Create a function to extract information from a PCAP file
def extract_pcap_info(file_path: str, label: str, progress=None) -> list:

    try:
        # Read the PCAP file using Scapy
        packets = rdpcap(file_path)

        output_data = []

        if progress:
            # Create a task for the inner loop
            packet_task = progress.add_task(
                f"[blue]Processing packets...", total=len(packets)
            )

        for packet in packets:
            # Timestamp
            timestamp = IEextractor.extractTimestamp(packet)

            # Source MAC address
            mac_address = IEextractor.extractMAC(packet)

            # Channel number
            channel = IEextractor.extractChannel(packet)

            # DS Parameter Set channel number
            ds_channel = IEextractor.extractDSChannel(packet)

            # HT Capabilities (HEX)
            htcapabilities = IEextractor.extractHTCapabilities(packet)

            # Extended Capabilities (HEX)
            extended_capabilities = IEextractor.extractExtendedCapabilities(packet)

            # Vendor Specific Tags (HEX)
            vendor_specific_tags = IEextractor.extractVendorSpecificTags(packet)

            # Additional features

            # SSID
            ssid = IEextractor.extractSSID(packet)

            # Supported Rates (HEX)
            supported_rates = IEextractor.extractSupportedRates(packet)

            # Extended Supported Rates (HEX)
            extended_supported_rates = IEextractor.extractExtendedSupportedRates(packet)

            # VHT Capabilities (HEX)
            vhtcapabilities = IEextractor.extractVHTCapabilities(packet)

            # HE Capabilities (HEX)
            hecapabilities = IEextractor.extractHECapabilities(packet)

            # Packet size
            packet_length = len(packet)

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
                    packet_length,
                    label,
                ]
            )

            if progress:
                # Update the progress for each file
                progress.update(packet_task, advance=1)

        return output_data

    except Exception as e:
        logger.log.critical(f"Error extracting information from {file_path}: {e}")
        return RuntimeError
