from utils import logger, fieldUtility

from . import extendedCapExtractor

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Elt

import numpy as np


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
def extractHTCapabilities(packet: Dot11Elt) -> list:
    try:
        ht_cap = packet.getlayer(Dot11Elt, ID=45)

        # Extract all fields into a list

        fields_list = []

        ht_cap_list = [
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

        for field in ht_cap_list:
            fields_list.append(getattr(ht_cap, field))

        return fieldUtility.fieldPadder(fields_list, 53)
    except:
        logger.log.debug("No HT capabilities found.")
        return fieldUtility.noneList(53)


# Extract extended capabilities from packet
def extractExtendedCapabilities(packet) -> list:
    try:
        extendedCapHex = packet.getlayer(Dot11Elt, ID=127).info.hex()
        extendedCapBin = extendedCapExtractor.hex_string_to_binary(extendedCapHex)
        extendedCap = extendedCapExtractor.extract_fields_from_binary(
            extendedCapExtractor.EXTENDED_CAP, extendedCapBin
        )
        return extendedCap
    except:
        logger.log.debug("No extended capabilities found.")
        return fieldUtility.noneList(12)


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
        supportedRates = []

        rates = packet.getlayer(Dot11Elt, ID=1).rates

        for rate in rates:
            supportedRates.append(rate / 2)

        return fieldUtility.fieldPadder(supportedRates, 8)

    except:
        logger.log.debug("No supported rates found.")
        return fieldUtility.noneList(8)


# Extract extended supported rates from packet
def extractExtendedSupportedRates(packet):
    try:
        extendedSupportedRates = []

        rates = packet.getlayer(Dot11Elt, ID=50).rates

        for rate in rates:
            extendedSupportedRates.append(rate / 2)

        return fieldUtility.fieldPadder(extendedSupportedRates, 8)

    except:
        logger.log.debug("No extended supported rates found.")
        return fieldUtility.noneList(8)


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
