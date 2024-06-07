#!/bin/python

import hashlib
import sys

def extend_pcr(old_pcr_value, new_measurement, hash_algorithm='sha256'):
    """
    Extends a PCR value with a new measurement.

    Args:
        old_pcr_value (bytes): The current value of the PCR register.
        new_measurement (bytes): The new measurement to be extended into the PCR.
        hash_algorithm (str): The hash algorithm to be used (e.g., 'sha1', 'sha256').

    Returns:
        bytes: The new PCR value after extending with the new measurement.
    """
    # Concatenate the old PCR value and the new measurement
    input_data = old_pcr_value + new_measurement

    # Compute the new PCR value
    hash_obj = hashlib.new(hash_algorithm)
    hash_obj.update(input_data)
    new_pcr_value = hash_obj.digest()

    return new_pcr_value

def main():
    # Check if a string is provided as a command line argument
    if len(sys.argv) < 2:
        print("Usage: python script.py <string> [initial pcr value]")
        sys.exit(1)

    input_string = sys.argv[1].encode('utf-8')
    initial_pcr_value = bytes.fromhex(sys.argv[2]) if len(sys.argv) > 2 else b'\x00' * 32

    # Hash the input string using SHA-256
    measurement = hashlib.sha256(input_string).digest()
    print(f"Measurement (SHA-256 hash) for '{input_string.decode()}': {measurement.hex()}")

    extended_pcr = extend_pcr(initial_pcr_value, measurement, 'sha256')
    print(f"PCR value after extending with '{input_string.decode()}': {extended_pcr.hex()}")

if __name__ == "__main__":
    main()

