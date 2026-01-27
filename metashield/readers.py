import os
from PIL import Image
import piexif
from PyPDF2 import PdfReader
from mutagen.mp3 import MP3

def get_file_type(file_path):
    """
    Determine supported file type based on extension.
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext in ('.jpg', '.jpeg'):
        return 'image_jpg'
    elif ext == '.png':
        return 'image_png'
    elif ext == '.pdf':
        return 'pdf'
    elif ext == '.mp3':
        return 'mp3'
    else:
        return None

def read_metadata(file_path):
    """
    Read metadata from supported file types.
    Returns a dict representation.
    """
    file_type = get_file_type(file_path)
    if file_type is None:
        raise ValueError(f"Unsupported file type: {file_path}")
    
    metadata = {}
    
    try:
        if file_type == 'image_jpg':
            exif_data = piexif.load(file_path)
            for section in exif_data:
                if section != 'thumbnail':
                    metadata[section] = {piexif.TAGS[section].get(tag, {'name': str(tag)})['name']: exif_data[section][tag] for tag in exif_data[section]}
        elif file_type == 'image_png':
            with Image.open(file_path) as img:
                metadata = img.info
        elif file_type == 'pdf':
            reader = PdfReader(file_path)
            if reader.metadata:
                metadata = {k.lstrip('/'): v for k, v in reader.metadata.items()}
        elif file_type == 'mp3':
            audio = MP3(file_path)
            metadata = {key: str(audio[key]) for key in audio}
    except Exception as e:
        raise RuntimeError(f"Error reading metadata from {file_path}: {e}")
    
    return metadata