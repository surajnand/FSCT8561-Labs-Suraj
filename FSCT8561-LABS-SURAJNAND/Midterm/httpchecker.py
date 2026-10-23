
import requests
from urllib.parse import urlparse

# Instructor-provided local test website
BASE_URL = "http://127.0.0.1:8765"
TIMEOUT = 5

# Security headers to inspect
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy"
]

# Authorized local test paths
TEST_PATHS = [
    "/",
    "/health",
    "/redirect",
    "/missing"
]


def check_http_security():
    print("\n===== HTTP Security Assessment =====")
    print("Target:", BASE_URL)

    results = []

    # Create a session to reuse HTTP connections
    with requests.Session() as session:

        for path in TEST_PATHS:
            url = BASE_URL + path

            print(f"\nChecking: {url}")

            try:
                # Disable automatic redirects to inspect 3xx responses
                response = session.get(
                    url,
                    timeout=TIMEOUT,
                    allow_redirects=False
                )

                print("HTTP Status:", response.status_code)

                # Check for missing security headers
                missing_headers = []

                for header in SECURITY_HEADERS:
                    if header not in response.headers:
                        missing_headers.append(header)

                if missing_headers:
                    print("Missing security headers:")

                    for header in missing_headers:
                        print(" -", header)

                else:
                    print("All selected security headers present")

                # Check HTTP redirects
                redirect_location = None

                if 300 <= response.status_code < 400:
                    redirect_location = response.headers.get(
                        "Location"
                    )

                    print(
                        "Redirect Location:",
                        redirect_location or "Not provided"
                    )

                # Inspect Set-Cookie headers
                cookie_findings = []

                raw_cookies = []

                if hasattr(response.raw.headers, "getlist"):
                    raw_cookies = response.raw.headers.getlist(
                        "Set-Cookie"
                    )

                for cookie in raw_cookies:
                    cookie_name = cookie.split("=", 1)[0].strip()

                    attributes = [
                        part.strip().lower()
                        for part in cookie.split(";")[1:]
                    ]

                    missing_attributes = []

                    if "httponly" not in attributes:
                        missing_attributes.append("HttpOnly")

                    if "secure" not in attributes:
                        missing_attributes.append("Secure")

                    if not any(
                        attr.startswith("samesite=")
                        for attr in attributes
                    ):
                        missing_attributes.append("SameSite")

                    if missing_attributes:
                        print(
                            f"Cookie '{cookie_name}' missing:",
                            ", ".join(missing_attributes)
                        )

                    cookie_findings.append({
                        "cookie_name": cookie_name,
                        "missing_attributes": missing_attributes
                    })

                results.append({
                    "path": path,
                    "status_code": response.status_code,
                    "missing_headers": missing_headers,
                    "redirect_location": redirect_location,
                    "cookie_findings": cookie_findings
                })

            except requests.exceptions.Timeout:
                print("ERROR: HTTP request timed out")

                results.append({
                    "path": path,
                    "error": "TIMEOUT"
                })

            except requests.exceptions.ConnectionError:
                print("ERROR: Could not connect to website")

                results.append({
                    "path": path,
                    "error": "CONNECTION_FAILED"
                })

            except requests.exceptions.RequestException:
                print("ERROR: HTTP request failed")

                results.append({
                    "path": path,
                    "error": "REQUEST_FAILED"
                })

    print("\n===== HTTP Assessment Completed =====")

    return results


if __name__ == "__main__":
    check_http_security()
