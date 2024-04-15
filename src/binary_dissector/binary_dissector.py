from configparser import ConfigParser
import os
import cowsay
from rich.progress import Progress, BarColumn, TextColumn
from rich import traceback

from utils import fileUtility

traceback.install()


def main():

    # Clear shell
    os.system("clear")

    # Fun title
    cowsay.stegosaurus("Dissecting some bits...")

    # Import the config file
    config = ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "config.ini"))

    # # Define custom columns for the progress bar
    # custom_columns = [
    #     BarColumn(bar_width=None),
    #     " ",  # Spacer
    #     TextColumn("[progress.description]{task.description}"),
    #     TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    #     " ",  # Spacer
    #     TextColumn("[progress.remaining]{task.completed}/{task.total}"),
    # ]

    # # Create a Rich progress context
    # with Progress(*custom_columns) as progress:
    #     # Create a task for the outer loop
    #     dataset_task = progress.add_task(
    #         "[cyan]Processing datasets...", total=len(config.sections())
    #     )

    #     for i in config.sections():
    #         # Set dataset path and output path
    #         capture_path = config[i]["raw_path"]
    #         output_path = config[i]["output_path"]

    #         # List all pcap files in the directory
    #         pcap_files = [f for f in os.listdir(capture_path) if f.endswith(".pcap")]

    #         # Create a task for the inner loop
    #         file_task = progress.add_task(
    #             f"[green]Processing files in {i}...", total=len(pcap_files)
    #         )

    #         for filename in pcap_files:
    #             # Set output file name to the same as the PCAP file
    #             label = os.path.splitext(filename)[0]

    #             # Set the file path for the PCAP file
    #             file_path = os.path.join(capture_path, filename)

    #             # Extract information from the PCAP file
    #             info = PCAPextractor.extract_pcap_info(file_path, label, progress)

    #             if info:
    #                 # Check if the output folder exists
    #                 fileUtility.checkCreatePath(output_path)

    #                 fileUtility.csv_writer(HEADER, info, output_path, label)

    #             # Update the progress for each file
    #             progress.update(file_task, advance=1)

    #         # Update the progress for each dataset
    #         progress.update(dataset_task, advance=1)


if __name__ == "__main__":
    main()
