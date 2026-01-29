import requests

def fetch_spec_from_url(url: str) -> str:
    try:
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            raise ValueError(f"Failed to fetch spec. HTTP {response.status_code}")

        content_type = response.headers.get("content-type", "")

        if "json" not in content_type and "yaml" not in content_type and "text" not in content_type:
            raise ValueError("URL does not appear to return JSON or YAML content")

        return response.text

    except requests.exceptions.RequestException as e:
        raise ValueError(f"Error fetching URL: {str(e)}")
