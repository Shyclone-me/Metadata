import hashlib
import base64
import os
import json

def hash_file(file_path):
    """
    Compute SHA-256 hash of a file to verify integrity.
    """
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

def is_base64(s):
    """
    Check if a string is a valid Base64-encoded value.
    """
    if not isinstance(s, str) or len(s) % 4 != 0:
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def flatten_dict(d, parent_key='', sep='.'):
    """
    Flatten a nested dict for easier scanning.
    """
    items = {}
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(flatten_dict(v, new_key, sep))
        else:
            items[new_key] = v
    return items

def color_print(color, text):
    """
    Print text with ANSI color (for CLI, cross-platform, but may not work in all Windows terminals).
    """
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'reset': '\033[0m'
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")

def pretty_print_dict(d, indent=0):
    """
    Pretty-print a dict as a string (handles nested dicts). Updated for GUI use.
    """
    output = ''
    for key, value in sorted(d.items()):
        output += '  ' * indent + str(key) + ': '
        if isinstance(value, dict):
            output += '\n' + pretty_print_dict(value, indent + 1)
        else:
            output += str(value) + '\n'
    return output

def export_to_json(data, file_path):
    """
    Export dict to JSON file.
    """
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)