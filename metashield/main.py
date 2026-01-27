import argparse
import os
from utils import color_print, hash_file, pretty_print_dict, export_to_json
from readers import read_metadata, get_file_type
from editors import edit_file, remove_metadata, add_fake_metadata
from forensics import detect_suspicious, compare_metadata

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MetaShield: Metadata tool for privacy and forensics.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Read command
    read_p = subparsers.add_parser('read', help='Read and display metadata')
    read_p.add_argument('path', help='File or folder path')
    read_p.add_argument('--json', help='Export to JSON (single file only)')
    read_p.add_argument('--recursive', action='store_true', help='Recursive for folders')

    # Edit command
    edit_p = subparsers.add_parser('edit', help='Edit metadata (remove/modify sensitive fields)')
    edit_p.add_argument('path', help='File or folder path')
    edit_p.add_argument('--remove-gps', action='store_true', help='Remove GPS data')
    edit_p.add_argument('--remove-device', action='store_true', help='Remove device info (Make/Model)')
    edit_p.add_argument('--remove-author', action='store_true', help='Remove author/artist info')
    edit_p.add_argument('--set-author', help='Set author/artist name')
    edit_p.add_argument('--recursive', action='store_true', help='Recursive for folders')

    # Strip command
    strip_p = subparsers.add_parser('strip', help='Strip all metadata (anti-forensics)')
    strip_p.add_argument('path', help='File or folder path')
    strip_p.add_argument('--fake', action='store_true', help='Insert realistic fake metadata after strip')
    strip_p.add_argument('--recursive', action='store_true', help='Recursive for folders')

    # Detect command
    detect_p = subparsers.add_parser('detect', help='Detect suspicious metadata')
    detect_p.add_argument('path', help='File or folder path')
    detect_p.add_argument('--recursive', action='store_true', help='Recursive for folders')

    # Compare command
    compare_p = subparsers.add_parser('compare', help='Compare metadata between two files')
    compare_p.add_argument('file1', help='First file')
    compare_p.add_argument('file2', help='Second file')

    args = parser.parse_args()

    def handle_file(file_path, args):
        command = args.command
        try:
            if command == 'read':
                metadata = read_metadata(file_path)
                color_print('blue', f"Metadata for {file_path}:")
                print(pretty_print_dict(metadata))  # Use print for CLI
                if args.json and os.path.isfile(args.path):  # Only for single file
                    export_to_json(metadata, args.json)
                    color_print('green', f"Exported to {args.json}")
            elif command == 'edit':
                before_hash = hash_file(file_path)
                edit_file(file_path, args.remove_gps, args.remove_device, args.remove_author, args.set_author)
                after_hash = hash_file(file_path)
                color_print('green', f"Edited {file_path}")
                color_print('yellow', f"Hash before: {before_hash}")
                color_print('yellow', f"Hash after: {after_hash}")
            elif command == 'strip':
                before_hash = hash_file(file_path)
                remove_metadata(file_path)
                if args.fake:
                    add_fake_metadata(file_path)
                after_hash = hash_file(file_path)
                color_print('green', f"Stripped {file_path}" + (" and added fake metadata" if args.fake else ""))
                color_print('yellow', f"Hash before: {before_hash}")
                color_print('yellow', f"Hash after: {after_hash}")
            elif command == 'detect':
                susp = detect_suspicious(file_path)
                color_print('blue', f"Suspicious findings for {file_path}:")
                if susp:
                    for item in susp:
                        color_print('red', item)
                else:
                    color_print('green', "No suspicious metadata detected.")
        except Exception as e:
            color_print('red', f"Error processing {file_path}: {e}")

    if args.command == 'compare':
        try:
            added, removed, changed = compare_metadata(args.file1, args.file2)
            color_print('blue', f"Comparison between {args.file1} and {args.file2}:")
            if added:
                color_print('green', "Added keys:")
                for k in sorted(added):
                    print(k)
            if removed:
                color_print('red', "Removed keys:")
                for k in sorted(removed):
                    print(k)
            if changed:
                color_print('yellow', "Changed keys:")
                for k in sorted(changed):
                    print(k)
            if not (added or removed or changed):
                color_print('green', "No differences found.")
        except Exception as e:
            color_print('red', f"Error comparing files: {e}")
    else:
        path = args.path
        recursive = args.recursive
        if os.path.isfile(path):
            if get_file_type(path) is None:
                color_print('red', f"Unsupported file: {path}")
            else:
                handle_file(path, args)
        elif os.path.isdir(path):
            walk_iter = os.walk(path) if recursive else [(path, [], [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))])]
            for root, _, files in walk_iter:
                for file in files:
                    file_path = os.path.join(root, file)
                    if get_file_type(file_path):
                        handle_file(file_path, args)
        else:
            color_print('red', f"Invalid path: {path}")
        if args.command == 'read' and args.json and os.path.isdir(path):
            color_print('yellow', "--json option is only supported for single files.")