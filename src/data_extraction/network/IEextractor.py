from utils import logger

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Elt


# Convert channel frequency into channel number
def frequencyToChannel(frequency: int) -> int:
    """Convert channel frequency into channel number
    Args:
        frequency (int): Channel frequency
    Returns:
        int: Channel number
    """
    return int((frequency - 2407) / 5)


# Extract timestamp from packet
def extractTimestamp(packet) -> float:
    """Extract timestamp from packet
    Args:
        packet (scapy.layers.dot11.Dot11): Scapy packet
    Returns:
        float: Timestamp
    """
    return packet.time


# Extract source MAC address from packet
def extractMAC(packet) -> str:
    return packet.addr2


# Extract channel number from packet
def extractChannel(packet) -> int:
    return frequencyToChannel(packet.Channel)


# Extract DS channel number from packet
def extractDSChannel(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=3).channel
    except:
        logger.log.debug("No DS channel found.")
        return None


# Extract HT capabilities from packet
def extractHTCapabilities(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=45).info.hex()
    except:
        logger.log.debug("No HT capabilities found.")
        return None


# Extract extended capabilities from packet
def extractExtendedCapabilities(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=127).info.hex()
    except:
        logger.log.debug("No extended capabilities found.")
        return None


# Extract vendor specific tags from packet
def extractVendorSpecificTags(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=221).info.hex()
    except:
        logger.log.debug("No vendor specific tags found.")
        return None


# Extract SSID from packet
def extractSSID(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=0).info.decode()
    except:
        logger.log.debug("No SSID found.")
        return None


# Extract supported rates from packet
def extractSupportedRates(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=1).info.hex()
    except:
        logger.log.debug("No supported rates found.")
        return None


# Extract extended supported rates from packet
def extractExtendedSupportedRates(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=50).info.hex()
    except:
        logger.log.debug("No extended supported rates found.")
        return None


# Extract VHT capabilities from packet
def extractVHTCapabilities(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=191).info.hex()
    except:
        logger.log.debug("No VHT capabilities found.")
        return None


# Extract HE capabilities from packet
def extractHECapabilities(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=255).info.hex()
    except:
        logger.log.debug("No HE capabilities found.")
        return None
