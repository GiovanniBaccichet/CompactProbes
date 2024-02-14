from configparser import ConfigParser
import os
from rich.progress import Progress, BarColumn, TextColumn
from rich import traceback

import network.PCAPextractor as PCAPextractor

from utils import fileUtility

traceback.install()


def main():
    # Import the config file
    config = ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "config.ini"))

    # Define custom columns for the progress bar
    custom_columns = [
        BarColumn(bar_width=None),
        " ",  # Spacer
        TextColumn("[progress.description]{task.description}"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        " ",  # Spacer
        TextColumn("[progress.remaining]{task.completed}/{task.total}"),
    ]

    # Create a Rich progress context
    with Progress(*custom_columns) as progress:
        # Create a task for the outer loop
        dataset_task = progress.add_task(
            "[cyan]Processing datasets...", total=len(config.sections())
        )

        for i in config.sections():
            # Set dataset path and output path
            capture_path = config[i]["raw_path"]
            output_path = config[i]["output_path"]

            # List all pcap files in the directory
            pcap_files = [f for f in os.listdir(capture_path) if f.endswith(".pcap")]

            # Create a task for the inner loop
            file_task = progress.add_task(
                f"[green]Processing files in {i}...", total=len(pcap_files)
            )

            for filename in pcap_files:
                # Set output file name to the same as the PCAP file
                label = os.path.splitext(filename)[0]

                # Set the file path for the PCAP file
                file_path = os.path.join(capture_path, filename)

                # Extract information from the PCAP file
                info = PCAPextractor.extract_pcap_info(file_path, label, progress)

                if info:
                    # Check if the output folder exists
                    fileUtility.checkCreatePath(output_path)

                    # Write the information to a CSV file
                    header = [
                        "Timestamp",
                        "MAC Address",
                        "Channel",
                        "DS Channel",
                        "Extended Capabilities",
                        "Vendor Specific Tags",
                        "SSID",
                        "VHT Capabilities",
                        "HE Capabilities",
                        "Length",
                        "Label",
                        "Supported Rates 1",
                        "Supported Rates 2",
                        "Supported Rates 3",
                        "Supported Rates 4",
                        "Supported Rates 5",
                        "Supported Rates 6",
                        "Supported Rates 7",
                        "Supported Rates 8",
                        "Extended Supported Rates 1",
                        "Extended Supported Rates 2",
                        "Extended Supported Rates 3",
                        "Extended Supported Rates 4",
                        "Extended Supported Rates 5",
                        "Extended Supported Rates 6",
                        "Extended Supported Rates 7",
                        "Extended Supported Rates 8",
                        "L_SIG_TXOP_Protection",
                        "Forty_Mhz_Intolerant",
                        "PSMP",
                        "DSSS_CCK",
                        "Max_A_MSDU",
                        "Delayed_BlockAck",
                        "Rx_STBC",
                        "Tx_STBC",
                        "Short_GI_40Mhz",
                        "Short_GI_20Mhz",
                        "Green_Field",
                        "SM_Power_Save",
                        "Supported_Channel_Width",
                        "LDPC_Coding_Capability",
                        "res1",
                        "Min_MPDCU_Start_Spacing",
                        "Max_A_MPDU_Length_Exponent",
                        "res2",
                        "TX_Unequal_Modulation",
                        "TX_Max_Spatial_Streams",
                        "TX_RX_MCS_Set_Not_Equal",
                        "TX_MCS_Set_Defined",
                        "res3",
                        "RX_Highest_Supported_Data_Rate",
                        "res4",
                        "RX_MSC_Bitmask",
                        "res5",
                        "RD_Responder",
                        "HTC_HT_Support",
                        "MCS_Feedback",
                        "res6",
                        "PCO_Transition_Time",
                        "PCO",
                        "res7",
                        "Channel_Estimation_Capability",
                        "CSI_max_n_Rows_Beamformer_Supported",
                        "Compressed_Steering_n_Beamformer_Antennas_Supported",
                        "Noncompressed_Steering_n_Beamformer_Antennas_Supported",
                        "CSI_n_Beamformer_Antennas_Supported",
                        "Minimal_Grouping",
                        "Explicit_Compressed_Beamforming_Feedback",
                        "Explicit_Noncompressed_Beamforming_Feedback",
                        "Explicit_Transmit_Beamforming_CSI_Feedback",
                        "Explicit_Compressed_Steering",
                        "Explicit_Noncompressed_Steering",
                        "Explicit_CSI_Transmit_Beamforming",
                        "Calibration",
                        "Implicit_Trasmit_Beamforming",
                        "Transmit_NDP",
                        "Receive_NDP",
                        "Transmit_Staggered_Sounding",
                        "Receive_Staggered_Sounding",
                        "Implicit_Transmit_Beamforming_Receiving",
                    ]

                    fileUtility.csv_writer(header, info, output_path, label)

                # Update the progress for each file
                progress.update(file_task, advance=1)

            # Update the progress for each dataset
            progress.update(dataset_task, advance=1)


if __name__ == "__main__":
    main()
