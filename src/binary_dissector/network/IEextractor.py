from utils import logger

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Elt, Dot11FCS

from . import dictionaries

import numpy as np

# Extract source MAC address from packet
def getMAC(packet : Dot11Elt) -> str:
    return str(packet.addr2)

def getElementIDText(elementid: int) -> str:
    try:
        return dictionaries.ELEMENT_IDs[elementid]
    except:
        print(elementid)
        return "unknown"