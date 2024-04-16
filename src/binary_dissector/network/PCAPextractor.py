from utils import logger

from scapy.all import rdpcap

from network import IEextractor, dictionaries
from utils import fileUtility, binUtility


# Create a function to extract information from a PCAP file
def extract_pcap_info(file_path: str, label: str, progress=None) -> list:

    try:
        # Read the PCAP file using Scapy
        packets = rdpcap(file_path)

        output_data = []

        filename = fileUtility.get_substring_after_last_slash(file_path)

        if progress:
            # Create a task for the inner loop
            packet_task = progress.add_task(
                f"[blue]Processing packets: {filename}", total=len(packets)
            )

        for packet in packets:

            packet_bits = binUtility.getMACLayerBits(packet)

            packet_IE = packet_bits[192:]

            print(packet_IE)

            index = 0
            packetLength = len(packet_IE)
            elements = []

            while index < packetLength - 32:
                packet_slice = packet_IE[index:]
                elementID = binUtility.readBinElementID(packet_slice)
                convertedID = binUtility.readElementID(packet_slice)
                length = binUtility.readBinLength(packet_slice)
                field = binUtility.readBinField(packet_slice)

                elements.append(
                    (
                        dictionaries.ELEMENT_IDs[convertedID],
                        binUtility.convertBinLength(packet_slice),
                        elementID,
                        length,
                        field,
                    )
                )

                index += 16 + binUtility.convertBinLength(packet_slice)

            frame_check_seq = packet_IE[-32:]

            combined_list = (
                [
                    timestamp,
                    mac_address,
                    channel,
                    ds_channel,
                    seq_number,
                    vendor_specific_tags,
                    ssid,
                    vhtcapabilities,
                    hecapabilities,
                    packet_length,
                    label,
                ]
                + supported_rates  # add individual Supported Rates
                + extended_supported_rates  # add individual Extended Supported Rates
                + htcapabilities  # add individual HT Capabilities
                + extended_capabilities  # add individual Extended Capabilities
            )

            output_data.append(combined_list)

            if progress:
                # Update the progress for each file
                progress.update(packet_task, advance=1)

        return output_data

    except Exception as e:
        logger.log.critical(f"Error extracting information from {file_path}: {e}")
        return RuntimeError
