import os
import time
import json
import hashlib


class C:
    OK = '\033[92m'
    WARN = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'


def hash_file(filename):
    h = hashlib.sha256()
    try:
        with open(filename, 'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                h.update(chunk)
    except FileNotFoundError:
        #print(f"{C.WARN}Warning: '{filename}' not found. Skipping...{C.END}")
        return None
    except PermissionError:
        #print(f"{C.WARN}Warning: Permission denied for '{filename}'. Skipping...{C.END}")
        return None
    return h.hexdigest()


def hash_directory(directory_path):
    """
    Recursively hashes every file in the directory and subdirectories.
    Returns a dictionary of file paths to their hashes.
    """
    file_hashes = {}
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_hashes[file_path] = hash_file(file_path)
    return file_hashes


if __name__ == "__main__":
    invalid_files = []

    with open(os.path.abspath("files.json"), 'r') as rf:
        data = json.load(rf)

    # Initial check to categorize files and directories, and hash accordingly
    for item in data:
        if os.path.isdir(item['path']):
            item['is_directory'] = True
            item['file_hashes'] = hash_directory(item['path'])
        else:
            item['is_directory'] = False
            try:
                if item['original_hash'] is not None:
                    item['original_hash'] = hash_file(item['path'])
            except FileNotFoundError:
                invalid_files.append(item['path'])
                print(f"{C.WARN}{item['path']}: does not exist{C.END}")

    print()

    while True:
        for item in data:
            if item['is_directory']:
                current_file_hashes = hash_directory(item['path'])
                for file_path, current_hash in current_file_hashes.items():
                    original_hash = item['file_hashes'].get(file_path)
                    if original_hash is None:
                        print(f"{C.WARN}{file_path}: NEW FILE{C.END}")
                    elif current_hash != original_hash:
                        print(f"{C.FAIL}{file_path}: MODIFIED{C.END}")
                    else:
                        #print(f"{file_path}: {C.OK}OK{C.END}")
                        pass
                # Update the stored hashes to the current state
                item['file_hashes'] = current_file_hashes
            else:
                try:
                    current_hash = hash_file(item['path'])
                except FileNotFoundError:
                    if item['path'] not in invalid_files:
                        print(f"{C.FAIL}{item['path']}: DELETED{C.END}")
                    continue

                if current_hash == item.get('original_hash'):
                    #print(f"{item['path']}: {C.OK}OK{C.END}")
                    pass
                else:
                    print(f"{C.FAIL}{item['path']}: MODIFIED{C.END}")

        with open(os.path.abspath("files.json"), 'w', encoding='utf-8') as wf:
            json.dump(data, wf, ensure_ascii=False, indent=4)

        print()
        time.sleep(5)
