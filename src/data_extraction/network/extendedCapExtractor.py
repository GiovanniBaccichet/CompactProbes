EXTENDED_CAP = {
    0: "20_40_BSS_Coexistence_Management_Support",
    1: "Reserved_1",
    2: "Extended_Channel_Switching",
    3: "Reserved_2",
    4: "PSMP_Capability",
    5: "Reserved_3",
    6: "SPSMP_Support",
    7: "Event",
    8: "Diagnostics",
    9: "Multicast_Diagnostic",
    10: "Location_Tracking",
    11: "FMS",
    12: "Proxy_Arp_Service",
    13: "Collocated_Interference_Reporting",
    14: "Civic_Location",
    15: "Geospatial_Location",
    16: "TFS",
    17: "WNM_Sleep_Mode",
    18: "TIM_Broadcast",
    19: "BSS_Transition",
    20: "QoS_Traffic_Capability",
    21: "AC_Station_Count",
    22: "Multiple_BSSID",
    23: "Timing_Measurement",
    24: "Channel_Usage",
    25: "SSID_List",
    26: "DMS",
    27: "UTC_Timing",
    28: "TPU_Buffer_STA_Support",
    29: "TDLS_Peer_PSM",
    30: "TDLS_Channel_Switching",
    31: "Interworking",
    32: "QoS_Map",
    33: "EBR",
    34: "SSPN_Interface",
    35: "Reserved_4",
    36: "MSGCF_Capability",
    37: "TDLS_Support",
    38: "TDLS_Prohibited",
    39: "TDLS_Channel_Switching_Prohibited",
    40: "Reject_Unadmitted_Frame",
    41: "Service_Interval_Granularity",
    42: "Service_Interval_Granularity",
    43: "Service_Interval_Granularity",
    44: "Identifier_Location",
    45: "U_APSD_Coexistence",
    46: "WNM_Notification",
    47: "QAB_Capability",
    48: "UTF_8_SSID",
    49: "QMF_Activated",
    50: "QMF_ReconfigurationActivated",
    51: "Robust_AV_Streaming",
    52: "Advanced_GCR",
    53: "Mesh_GCR",
    54: "SCS",
    55: "QLoad_Report",
    56: "Alternate_EDCA",
    57: "Unprotected_TXOP",
    58: "Protected_RXOP",
    59: "Reserved_5",
    60: "Protected_QLoad_Report",
    61: "TDLS_Wide_Bandwidth",
    62: "Operating_Mode_Notification",
    63: "Max_Number_Of_MSDUs_In_A_MPDU",
    64: "Max_Number_Of_MSDUs_In_A_MPDU",
    65: "Channel_Schedule_Management",
    66: "Geodatabase_Inband_Enabling_Signal",
    67: "Network_Channel_Control",
    68: "White_Space_Map",
    69: "Channel_Availability_Query",
    70: "FTM_Responder",
    71: "FTM_Initiator",
    72: "Reserved_6",
    73: "ESM_Capability",
    74: "Future_Channel_Guidance",
}


def extract_fields_from_binary(ie_dictionary, binary_string):
    # Initialize a list to hold tuples of field names and their corresponding bits
    extracted_fields = []

    # Convert the binary string to a list for easier access by index, and reverse it
    binary_list = list(binary_string)

    # Initialize a set to keep track of fields already added
    added_fields = set()

    # Iterate through each bit index in the extended capabilities dictionary
    for bit_index in range(len(binary_list)):
        # Check if this bit index is in the dictionary (to handle binary strings longer than the dictionary)
        if bit_index in ie_dictionary:
            field_name = ie_dictionary[bit_index]
            # If the field has not been added yet, proceed to extract its bits
            if field_name not in added_fields:
                # Find all bit indexes for this field
                bit_indexes = [
                    index for index, name in ie_dictionary.items() if name == field_name
                ]
                # Extract bits for the current field
                field_bits = "".join(
                    [
                        binary_list[index] if index < len(binary_list) else "0"
                        for index in bit_indexes
                    ]
                )
                # Add the field and its bits to the list
                extracted_fields.append((field_name, field_bits))
                # Mark this field as added
                added_fields.add(field_name)

    return extracted_fields
