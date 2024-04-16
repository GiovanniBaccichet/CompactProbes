from utils import logger, fieldUtility

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Elt, Dot11FCS

import numpy as np

# Extract source MAC address from packet
def extractMAC(packet) -> str:
    return packet.addr2