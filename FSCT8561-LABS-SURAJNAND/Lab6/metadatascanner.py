
from pathlib import Path
from PIL import Image, ExifTags
import base64
import binascii
import csv
import re
import xml.etree.ElementTree as ET

# Lab 6 - Automated Metadata Scanner
# Scans EXIF, PNG text, and XMP metadata.

BASE_DIR = Path(__file__).resolve().parent
image_dir = BASE_DIR / "Images"
output_file = BASE_DIR / "metadata_report.csv"

results = []

# These are investigation indicators, not hard-coded secrets.
stage_pattern = re.compile(
    r"\b(RECON|VULN|EXPLOIT|PERSIST|LATERAL|EXFIL)\s*:",
    re.IGNORECASE
)

suspicious_fields = (
    "description", "comment", "copyright",
    "software", "makernote", "subject",
    "title", "keywords"
)


def clean_value(value):
    """Convert metadata to readable text."""
    if isinstance(value, bytes):
        if value.startswith(b"ASCII\x00\x00\x00"):
            value = value[8:]

        return value.decode(
            "utf-8", errors="replace"
        ).strip("\x00 ")

    return str(value).strip()


def decode_base64(value):
    """Decode valid Base64 containing readable text."""
    value = value.strip()

    if len(value) < 16:
        return None

    if not re.fullmatch(
        r"[A-Za-z0-9+/]+={0,2}", value
    ):
        return None

    try:
        decoded = base64.b64decode(
            value, validate=True
        ).decode("utf-8")

        if decoded.isprintable():
            return decoded

    except (
        ValueError,
        UnicodeError,
        binascii.Error
    ):
        pass

    return None


def extract_xmp(value):
    """Extract individual XML elements from XMP."""
    fields = []

    text = clean_value(value)

    try:
        root = ET.fromstring(text)

        for element in root.iter():
            if element.text and element.text.strip():
                name = element.tag.split("}")[-1]
                fields.append((
                    f"XMP/{name}",
                    element.text.strip()
                ))

            for attribute, attribute_value in (
                element.attrib.items()
            ):
                name = attribute.split("}")[-1]
                fields.append((
                    f"XMP/{name}",
                    attribute_value
                ))

    except ET.ParseError:
        fields.append(("XMP/raw", text))

    return fields


def extract_metadata(img):
    """Collect EXIF, PNG text, and XMP fields."""
    fields = []
    exif = img.getexif()

    # Standard EXIF
    for tag_id, value in exif.items():
        name = ExifTags.TAGS.get(
            tag_id, str(tag_id)
        )

        if name in ("ExifOffset", "GPSInfo"):
            continue

        fields.append((
            f"EXIF/{name}",
            clean_value(value)
        ))

    # Nested EXIF
    for ifd_name, ifd_id in (
        ExifTags.IFD.__members__.items()
    ):
        try:
            nested = exif.get_ifd(ifd_id)

            for tag_id, value in nested.items():
                name = ExifTags.TAGS.get(
                    tag_id, str(tag_id)
                )

                fields.append((
                    f"EXIF/{ifd_name}/{name}",
                    clean_value(value)
                ))

        except (KeyError, TypeError, ValueError):
            continue

    # PNG text and XMP
    for key, value in img.info.items():
        if key.lower() == "exif":
            continue

        if "xmp" in key.lower():
            fields.extend(extract_xmp(value))
            continue

        # Exclude ordinary image properties
        if key.lower() in ("srgb", "gamma", "dpi"):
            continue

        fields.append((
            f"PNG/{key}",
            clean_value(value)
        ))

    return fields


def analyze_metadata(fields):
    """Find evidence and assign a heuristic score."""
    confirmed = []
    encoded_suspicious = []
    other_indicators = []

    for field, raw_value in fields:
        value = clean_value(raw_value)
        decoded = decode_base64(value)
        message = decoded if decoded else value

        # Only inspect meaningful metadata fields.
        field_is_relevant = any(
            word in field.lower()
            for word in suspicious_fields
        )

        if not field_is_relevant:
            continue

        # A recognizable attack-stage marker
        match = stage_pattern.search(message)

        if match:
            confirmed.append((
                field,
                "Base64" if decoded else "Plain text",
                message
            ))

        elif decoded:
            encoded_suspicious.append((
                field, decoded
            ))

        elif (
            len(value) > 40
            and any(word in value.lower() for word in (
                "payload", "reverse shell",
                "credential", "covert channel"
            ))
        ):
            other_indicators.append(field)

    # Remove duplicate fields
    confirmed = list(dict.fromkeys(confirmed))
    encoded_suspicious = list(
        dict.fromkeys(encoded_suspicious)
    )
    other_indicators = list(
        dict.fromkeys(other_indicators)
    )

    score = 0
    reasons = []
    suspected = []
    encodings = []
    messages = []

    if confirmed:
        score += 10
        reasons.append(
            "+10: Confirmed lab covert-message "
            "marker found in metadata"
        )

        for field, encoding, message in confirmed:
            suspected.append(field)
            encodings.append(encoding)
            messages.append(message)

    # Avoid double-counting the confirmed Base64 clue.
    if encoded_suspicious:
        score += 5
        reasons.append(
            "+5: Additional Base64-encoded "
            "metadata requires investigation"
        )

        for field, message in encoded_suspicious:
            suspected.append(field)
            encodings.append("Possible Base64")

    # Count a distinct unusual indicator only.
    if other_indicators:
        score += 5
        reasons.append(
            "+5: Additional unusual metadata "
            "content found"
        )
        suspected.extend(other_indicators)

    if not reasons:
        reasons.append(
            "No suspicious indicators identified"
        )

    return {
        "suspected_field": "; ".join(
            dict.fromkeys(suspected)
        ),
        "encoding": "; ".join(
            dict.fromkeys(encodings)
        ) or "None",
        "risk_score": score,
        "reason": "; ".join(reasons),
        "recovered_message": "; ".join(messages)
    }


def scan_images():
    """Scan images and export the CSV report."""
    if not image_dir.is_dir():
        print("Images folder not found:", image_dir)
        return

    images = sorted(image_dir.glob("*.png"))

    if not images:
        print("No PNG images found.")
        return

    for image_path in images:
        print(f"\nScanning: {image_path.name}")

        try:
            with Image.open(image_path) as img:
                fields = extract_metadata(img)
                analysis = analyze_metadata(fields)

                row = {
                    "filename": image_path.name,
                    "format": img.format,
                    "metadata_fields": "; ".join(
                        dict.fromkeys(
                            field for field, value in fields
                        )
                    ),
                    **analysis
                }

                results.append(row)

                print(
                    "Suspected field:",
                    row["suspected_field"]
                )
                print("Encoding:", row["encoding"])
                print("Risk score:", row["risk_score"])
                print("Reason:", row["reason"])
                print(
                    "Recovered message:",
                    row["recovered_message"]
                )

        except (OSError, ValueError) as error:
            print("Error:", error)

    if not results:
        print("No images were successfully scanned.")
        return

    # Export one CSV row per image
    with open(
        output_file, "w",
        newline="", encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=list(results[0].keys())
        )

        writer.writeheader()
        writer.writerows(results)

    print("\n=== SCAN COMPLETE ===")
    print("Images scanned:", len(results))
    print("CSV saved:", output_file)


if __name__ == "__main__":
    scan_images()
