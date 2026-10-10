# Import one PoC package (positive or negative) into the local Argilla server
# through the official SDK entry point Dataset.from_disk().
#
# Usage: python import_poc.py samples/poc-positive

import sys

import argilla as rg

API_URL = "http://localhost:6900"
API_KEY = "argilla.apikey"


def main() -> None:
    path = sys.argv[1]
    client = rg.Argilla(api_url=API_URL, api_key=API_KEY)
    dataset = rg.Dataset.from_disk(path, client=client)
    print(f"[+] from_disk({path!r}) returned without error")
    print(f"[+] imported dataset name : {dataset.name!r}")
    print(f"[+] imported dataset id   : {dataset.id}")
    print(f"[+] imported dataset ws   : {dataset.workspace.name}")
    print(f"[+] settings URL in UI    : {API_URL}/dataset/{dataset.id}/settings")


if __name__ == "__main__":
    main()
