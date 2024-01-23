import logging

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11Elt


# Create a function to extract information from a PCAP file
def extract_pcap_info(file_path, label):
    try:
        # Read the PCAP file using Scapy
        packets = rdpcap(file_path)

        output_data = []

        for packet in packets:
            # Timestamp
            timestamp = extractTimestamp(packet)

            # Source MAC address
            mac_address = extractMAC(packet)

            # Channel number
            channel = extractChannel(packet)

            # DS Parameter Set channel number
            ds_channel = extractDSChannel(packet)

            # HT Capabilities (HEX)
            htcapabilities = extractHTCapabilities(packet)

            # Extended Capabilities (HEX)
            extended_capabilities = extractExtendedCapabilities(packet)

            # Vendor Specific Tags (HEX)
            vendor_specific_tags = extractVendorSpecificTags(packet)

            # SSID
            ssid = extractSSID(packet)

            # Supported Rates (HEX)
            supported_rates = extractSupportedRates(packet)

            output_data.append(
                [
                    timestamp,
                    mac_address,
                    channel,
                    ds_channel,
                    htcapabilities,
                    extended_capabilities,
                    vendor_specific_tags,
                    label,
                ]
            )

        return output_data
    
    except Exception as e:
        print(f"[!] Error processing {file_path}: {str(e)}")
        return RuntimeError


# Convert channel frequency into channel number
def frequencyToChannel(frequency):
    return int((frequency - 2407) / 5)

# Extract timestamp from packet
def extractTimestamp(packet):
    return packet.time

# Extract source MAC address from packet
def extractMAC(packet):
    return packet.addr2

# Extract channel number from packet
def extractChannel(packet):
    return frequencyToChannel(packet.Channel)

# Extract DS channel number from packet
def extractDSChannel(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=3).channel
    except:
        return "0"
    
# Extract HT capabilities from packet
def extractHTCapabilities(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=45).info.hex()
    except:
        return "0"
    
# Extract extended capabilities from packet
def extractExtendedCapabilities(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=127).info.hex()
    except:
        return "0"
    
# Extract vendor specific tags from packet
def extractVendorSpecificTags(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=221).info.hex()
    except:
        return "0"
    
# Extract SSID from packet
def extractSSID(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=0).info.decode()
    except:
        return "0"
    
# Extract supported rates from packet
def extractSupportedRates(packet):
    try:
        return packet.getlayer(Dot11Elt, ID=1).info.hex()
    except:
        return "0"