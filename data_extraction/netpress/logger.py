import logging
from rich.logging import RichHandler

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

FORMAT = "%(message)s"
logging.basicConfig(
    level="DEBUG",
    format=FORMAT,
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)

log = logging.getLogger("rich")

log.setLevel("INFO")