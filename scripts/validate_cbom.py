import argparse
import json
import pathlib
import sys
import urllib.request

from jsonschema import Draft7Validator, FormatChecker


SCHEMA_URL = "https://cyclonedx.org/schema/bom-1.6.schema.json"


def load_document(path):
    if path.suffix.lower() == ".zip":
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
        import core

        return core.run(path.read_bytes(), name=path.name)["cbom"]
    return json.loads(path.read_text(encoding="utf-8"))


def load_schema(path):
    if path:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    request = urllib.request.Request(SCHEMA_URL, headers={"User-Agent": "QScan-CBOM-Validator/1.0"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description="Validate a QScan CBOM against CycloneDX 1.6.")
    parser.add_argument("document", type=pathlib.Path, help="CBOM JSON or scanned ZIP file")
    parser.add_argument("--schema", help="Optional local CycloneDX 1.6 JSON schema")
    args = parser.parse_args()

    document = load_document(args.document)
    schema = load_schema(args.schema)
    validator = Draft7Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        for error in errors:
            location = ".".join(str(part) for part in error.path) or "$"
            print(f"{location}: {error.message}")
        raise SystemExit(1)
    print(f"Valid CycloneDX 1.6 CBOM: {args.document}")


if __name__ == "__main__":
    main()