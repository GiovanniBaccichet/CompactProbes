from configparser import ConfigParser
import os
from rich.progress import Progress, BarColumn, TextColumn
from rich import traceback

from utils import title

import argparse

traceback.install()


def main():

    title.print_title()

    parser = argparse.ArgumentParser(description="AsymMetric pairwise BOOsting")
    parser.add_argument("-M", type=int, help="number of iterations (filters)")
    args = parser.parse_args()

    if args.M is None:
        print('[!] Argument M is missing! Setting it to 1.')
        args.M = 1

    # Import the config file
    config = ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "config.ini"))

    print(config["DEFAULT"]["df_strings"])


if __name__ == "__main__":
    main()
