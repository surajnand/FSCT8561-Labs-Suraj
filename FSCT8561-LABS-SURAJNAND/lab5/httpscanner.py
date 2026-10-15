import requests
import csv
import json

BASE_URL = "http://127.0.0.1:3000"

def scan_endpoint(endpoint, method="GET", params=None, data=None):
    url = BASE_URL + endpoint

    # Record the input sent with each request
    request_input = params if method == "GET" else data

    try:
        if method == "GET":
            response = requests.get(url, params=params, timeout=5)

        elif method == "POST":
            response = requests.post(url, json=data, timeout=5)

        else:
            raise ValueError("Unsupported HTTP method")

        return {
            "method": method,
            "endpoint": endpoint,
            "input": json.dumps(request_input),
            "status_code": response.status_code,
            "response_length": len(response.content),
            "content_type": response.headers.get("Content-Type", ""),
            "server": response.headers.get("Server", ""),
            "error": ""
        }

    except requests.RequestException as error:
        return {
            "method": method,
            "endpoint": endpoint,
            "input": json.dumps(request_input),
            "status_code": "ERROR",
            "response_length": 0,
            "content_type": "",
            "server": "",
            "error": str(error)
        }


# Store scan results
results = []

# Test the homepage
results.append(scan_endpoint("/"))

# Test two search terms
for term in ["apple", "banana"]:
    results.append(
        scan_endpoint(
            "/rest/products/search",
            method="GET",
            params={"q": term}
        )
    )

# Test POST request
results.append(
    scan_endpoint(
        "/rest/products/search",
        method="POST",
        data={"q": "apple"}
    )
)

# Display the results
for result in results:
    print(result)

# Save the results to CSV
fieldnames = [
    "method",
    "endpoint",
    "input",
    "status_code",
    "response_length",
    "content_type",
    "server",
    "error"
]

with open("http_scan_results.csv", "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

print("\nHTTP scan completed.")
print("Results saved to http_scan_results.csv")