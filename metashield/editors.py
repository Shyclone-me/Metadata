import os
import random
from PIL import Image
import piexif
from PyPDF2 import PdfReader, PdfWriter
from mutagen.mp3 import MP3
from readers import get_file_type

def remove_metadata(file_path):
    """
    Strip all metadata from the file while preserving content.
    """
    file_type = get_file_type(file_path)
    if file_type is None:
        raise ValueError(f"Unsupported file type: {file_path}")
    
    backup = file_path + '.bak'
    os.rename(file_path, backup)
    try:
        if file_type == 'image_jpg':
            piexif.remove(backup, file_path)
        elif file_type == 'image_png':
            with Image.open(backup) as img:
                img.info = {}
                img.save(file_path)
        elif file_type == 'pdf':
            reader = PdfReader(backup)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            with open(file_path, 'wb') as f:
                writer.write(f)
        elif file_type == 'mp3':
            audio = MP3(backup)
            audio.delete()
            audio.save(file_path)
    except Exception as e:
        os.rename(backup, file_path)
        raise RuntimeError(f"Error stripping metadata from {file_path}: {e}")
    finally:
        if os.path.exists(backup):
            os.remove(backup)

def edit_file(file_path,
              remove_gps=False, remove_device=False, remove_author=False,
              set_author=None, set_title=None, set_comment=None, set_software=None):
    """
    Edit specific metadata fields safely.
    Now supports setting title, comment, and software/creator tool.
    """
    file_type = get_file_type(file_path)
    if file_type is None:
        raise ValueError(f"Unsupported file type: {file_path}")
    
    backup = file_path + '.bak'
    os.rename(file_path, backup)
    try:
        if file_type == 'image_jpg':
            exif_data = piexif.load(backup)
            if remove_gps and 'GPS' in exif_data:
                del exif_data['GPS']
            if remove_device:
                if 271 in exif_data['0th']: del exif_data['0th'][271]     # Make
                if 272 in exif_data['0th']: del exif_data['0th'][272]     # Model
            if remove_author:
                if 315 in exif_data['0th']: del exif_data['0th'][315]     # Artist
                if 40093 in exif_data.get('Exif', {}): del exif_data['Exif'][40093]  # XPAuthor

            # Set new values (only if provided)
            if set_author is not None:
                exif_data['0th'][315] = set_author.encode('utf-8')       # Artist
            if set_title is not None:
                exif_data['0th'][270] = set_title.encode('utf-8')        # ImageDescription
            if set_comment is not None:
                exif_data['Exif'][42032] = set_comment.encode('utf-8')   # UserComment
            if set_software is not None:
                exif_data['0th'][305] = set_software.encode('utf-8')     # Software

            piexif.insert(piexif.dump(exif_data), backup, file_path)

        elif file_type == 'image_png':
            with Image.open(backup) as img:
                info = img.info.copy()
                if remove_author:
                    for key in ['Author', 'Copyright', 'Comment']:
                        info.pop(key, None)
                if remove_device:
                    for key in ['Software', 'Source']:
                        info.pop(key, None)

                if set_author is not None:    info['Author']    = set_author
                if set_title is not None:     info['Title']     = set_title
                if set_comment is not None:   info['Comment']   = set_comment
                if set_software is not None:  info['Software']  = set_software

                img.info = info
                img.save(file_path)

        elif file_type == 'pdf':
            reader = PdfReader(backup)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            meta = dict(reader.metadata or {})
            if remove_author and '/Author' in meta:
                del meta['/Author']

            if set_author is not None:    meta['/Author']    = set_author
            if set_title is not None:     meta['/Title']     = set_title
            if set_comment is not None:   meta['/Subject']   = set_comment   # or /Keywords
            if set_software is not None:  meta['/Creator']   = set_software   # or /Producer

            writer.add_metadata({f'/{k}': v for k, v in meta.items()})
            with open(file_path, 'wb') as f:
                writer.write(f)

        elif file_type == 'mp3':
            audio = MP3(backup)
            if remove_author:
                audio.pop('TPE1', None)  # Artist
                audio.pop('TCOM', None)  # Composer

            if remove_device:
                audio.pop('TSSE', None)  # Encoded-by / Software

            if set_author is not None:    audio['TPE1'] = set_author          # Artist
            if set_title is not None:     audio['TIT2'] = set_title           # Title
            if set_comment is not None:   audio['COMM'] = set_comment         # Comment
            if set_software is not None:  audio['TSSE'] = set_software        # Encoded by

            audio.save(file_path)

    except Exception as e:
        os.rename(backup, file_path)
        raise RuntimeError(f"Error editing {file_path}: {e}")
    finally:
        if os.path.exists(backup):
            os.remove(backup)

def add_fake_metadata(file_path):
    """
    Insert realistic fake metadata after stripping.
    """
    file_type = get_file_type(file_path)
    if file_type is None:
        raise ValueError(f"Unsupported file type: {file_path}")
    
    try:
        if file_type == 'image_jpg':
            exif_data = piexif.load(file_path) if os.path.exists(file_path) else {'0th': {}, 'Exif': {}, 'GPS': {}, 'Interop': {}, '1st': {}, 'thumbnail': None}
            makes = ['Canon', 'Nikon', 'Sony', 'Samsung', 'Apple']
            exif_data['0th'][271] = random.choice(makes).encode('utf-8')  # Make
            exif_data['0th'][272] = (random.choice(makes) + ' FakeModel').encode('utf-8')  # Model
            exif_data['0th'][315] = 'Fake Artist'.encode('utf-8')  # Artist
            # Fake GPS
            lat = random.uniform(-90, 90)
            lon = random.uniform(-180, 180)
            def deg_to_dms(deg):
                d = int(deg)
                m = int((deg - d) * 60)
                s = (deg - d - m / 60) * 3600
                return ((abs(d), 1), (abs(m), 1), (int(abs(s) * 100), 100))
            exif_data['GPS'][piexif.GPSIFD.GPSLatitudeRef] = b'N' if lat >= 0 else b'S'
            exif_data['GPS'][piexif.GPSIFD.GPSLatitude] = deg_to_dms(lat)
            exif_data['GPS'][piexif.GPSIFD.GPSLongitudeRef] = b'E' if lon >= 0 else b'W'
            exif_data['GPS'][piexif.GPSIFD.GPSLongitude] = deg_to_dms(lon)
            piexif.insert(piexif.dump(exif_data), file_path, file_path)
        elif file_type == 'image_png':
            with Image.open(file_path) as img:
                info = img.info
                info['Software'] = 'Fake Software'
                info['Author'] = 'Fake Author'
                info['Comment'] = 'This is a fake comment'
                img.info = info
                img.save(file_path)
        elif file_type == 'pdf':
            reader = PdfReader(file_path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            meta = {
                '/Author': 'Fake Author',
                '/Producer': 'Fake Producer',
                '/Title': 'Fake Title'
            }
            writer.add_metadata(meta)
            temp_path = file_path + '.tmp'
            with open(temp_path, 'wb') as f:
                writer.write(f)
            os.rename(temp_path, file_path)
        elif file_type == 'mp3':
            audio = MP3(file_path)
            audio['TIT2'] = 'Fake Title'  # Title
            audio['TPE1'] = 'Fake Artist'  # Artist
            audio['TALB'] = 'Fake Album'  # Album
            audio.save()
    except Exception as e:
        raise RuntimeError(f"Error adding fake metadata to {file_path}: {e}")