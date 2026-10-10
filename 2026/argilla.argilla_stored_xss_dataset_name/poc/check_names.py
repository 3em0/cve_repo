# Print the dataset names exactly as stored server-side, from the raw JSON API.
# This proves the payload crosses the server and is persisted verbatim.

import json

import httpx

API_URL = "http://localhost:6900"
API_KEY = "argilla.apikey"


def main() -> None:
    r = httpx.get(f"{API_URL}/api/v1/me/datasets", headers={"X-Argilla-Api-Key": API_KEY})
    print(f"GET {API_URL}/api/v1/me/datasets -> HTTP {r.status_code}")
    items = r.json()["items"]
    print(f"datasets visible to the owner account: {len(items)}")
    for item in items:
        print(f"  {item['id']}  name={json.dumps(item['name'], ensure_ascii=False)}")


if __name__ == "__main__":
    main()
