import yaml
import json

def parse_spec(file, spec_text):
    try:
        # Case 1: File upload
        if file:
            content = file.file.read()

            # Convert bytes → string
            if isinstance(content, bytes):
                content = content.decode("utf-8")

        # Case 2: Raw text body
        elif spec_text:
            content = spec_text

        else:
            raise ValueError("No OpenAPI specification provided")

        # Parse YAML or JSON
        return yaml.safe_load(content)

    except Exception as e:
        raise ValueError(f"Invalid OpenAPI spec: {str(e)}")
