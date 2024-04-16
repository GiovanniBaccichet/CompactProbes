from utils import logger

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Elt, Dot11FCS

from . import dictionaries

import numpy as np

# Extract source MAC address from packet
def extractMAC(packet) -> str:
    return packet.addr2

def getElementIDText(elementid: int) -> str:
    try:
        return dictionaries.ELEMENT_IDs[elementid]
    except:
        logger.log.critical(f"Error extracting element id {elementid}: {e}")
        return RuntimeError