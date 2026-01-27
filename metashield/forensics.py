from readers import read_metadata
from utils import flatten_dict, is_base64

def detect_suspicious(file_path):
    """
    Detect suspicious metadata (Base64, hidden comments).
    Returns list of findings.
    """
    metadata = read_metadata(file_path)
    flat = flatten_dict(metadata)
    suspicious = []
    for key, val in flat.items():
        if isinstance(val, (str, bytes)):
            val_str = val if isinstance(val, str) else val.decode('utf-8', errors='ignore')
            if is_base64(val_str):
                suspicious.append(f"Base64-encoded string in {key}: {val_str}")
            if 'comment' in key.lower() or 'description' in key.lower():
                if 'hidden' in val_str.lower() or len(val_str) > 500:  # Heuristic for hidden/long comments
                    suspicious.append(f"Potential hidden comment in {key}: {val_str[:100]}...")
    return suspicious

def compare_metadata(file1, file2):
    """
    Compare metadata dicts.
    Returns (added, removed, changed) sets of keys.
    """
    md1 = read_metadata(file1)
    md2 = read_metadata(file2)
    flat1 = flatten_dict(md1)
    flat2 = flatten_dict(md2)
    added = set(flat2) - set(flat1)
    removed = set(flat1) - set(flat2)
    changed = {k for k in flat1 if k in flat2 and flat1[k] != flat2[k]}
    return added, removed, changed