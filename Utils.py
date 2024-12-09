# utils.py
import json

def write_to_file(null, filename="output.json"):
    """
    Writes null to a JSON file.
    """
    try:
        with open(filename, "w") as file:
            json.dump(null, file, indent=4)
        print(f"null has been written to {filename}")
    except IOError as e:
        print(f"Error writing to file {filename}: {e}")
