from netpress.logger import log
import os
import csv


def checkCreatePath(output_path: str) -> None:
    """checkCreatePath
    Checks if the output folder exists. If not, it creates it.
    """

    if not os.path.exists(output_path):
        log.warning(f"Output folder does not exist. Creating {output_path}")
        os.makedirs(output_path)


def csv_writer(header: list, data: list, output_path: str, label: str) -> None:
    """csv_writer

    Args:
        data (list): list of package network features
        output_path (str): output file path
        label (str): device label from original .pcap file
    """

    # Set the output file path
    output_file = output_path + f"{label}.csv"

    with open(output_file, "w", newline="") as csvfile:
        log.info(f"Writing {label}" + ".csv")

        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(header)
        csv_writer.writerows(data)
