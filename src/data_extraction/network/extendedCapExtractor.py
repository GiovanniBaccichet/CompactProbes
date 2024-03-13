from .constants import EXTENDED_CAP


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
