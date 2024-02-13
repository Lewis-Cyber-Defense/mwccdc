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

   with open(filename,'rb') as file:
       chunk = 0
       while chunk != b'':
           chunk = file.read(1024)
           h.update(chunk)

   return h.hexdigest()


if __name__ == "__main__":
    invalid_files = []

    with open(os.path.abspath("files.json") ,'r') as rf:
        data = json.load(rf)

    for file in data:
        try:
            if file['original_hash'] is not None:
                file['original_hash'] = hash_file(file['path'])
        except FileNotFoundError:
            invalid_files.append(file['path'])
            print(f"{C.WARN}{file['path']}: does not exist{C.END}")
    print()

    while True:
        for file in data:
            try:
                file['current_hash'] = hash_file(file['path'])
            except FileNotFoundError:
                if file['path'] not in invalid_files:
                    print(f"{C.FAIL}{file['path']}: DELETED{C.END}")
                continue

            if file['current_hash'] == file['original_hash']:
                print(f"{file['path']}: {C.OK}OK{C.END}")
            else:
                print(f"{C.FAIL}{file['path']}: MODIFIED{C.END}")

            with open(os.path.abspath("files.json") ,'w', encoding='utf-8') as wf:
                json.dump(data, wf, ensure_ascii=False, indent=4)

        print()
        time.sleep(5)