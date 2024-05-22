import logging
from rich.logging import RichHandler

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

FORMAT = "%(message)s"
logging.basicConfig(
    filename='bamboo.log',
    filemode='a',
    level="NOTSET",
    format=FORMAT,
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)

log = logging.getLogger("rich")

log.setLevel("INFO")

def print_best_config(best_configs : tuple) -> None:
    log.info(f"Best Filter: {str(best_configs[0])}")
    log.info(f"Best Threshold: {str(best_configs[1])}")
    log.info(f"Min error: {best_configs[2]}")
    log.info(f"Confidence: {best_configs[3]}")
