# FSCT 8561 — Operation Sentinel Midterm

## Project Overview

For my FSCT 8561 midterm, I created a Python application called Operation Sentinel. The purpose of this project was to combine the different networking and security concepts I learned throughout Labs 0–5 into one working application.

My application uses a TCP client and server that communicate with each other using sockets. Before the user can access the main menu, they need to enter the correct username and password, followed by a six-digit TOTP code for multi-factor authentication.

Once authenticated, the user can analyze a PCAP file, scan local TCP ports, and check a website for basic HTTP security issues. I used Python libraries such as socket, hashlib, pyotp, Scapy, and requests to build these features.

The application was designed for local testing using the resources provided by the instructor.

## Project Files

I separated the application into different Python files to keep the code organized and make each component easier to work with.

| File | Purpose |
|---|---|
| `server.py` | Runs the TCP server and handles authentication, authorization, client requests, and security logging. |
| `client.py` | Connects to the server and provides the main menu for the user. |
| `authentication.py` | Handles password verification and TOTP authentication. |
| `protocol.py` | Handles the JSON messages sent between the client and server. |
| `portscanner.py` | Scans a selected range of TCP ports on localhost. |
| `httpchecker.py` | Checks the local test website for HTTP security issues. |
| `pcapanalyzer.py` | Uses Scapy to analyze the provided PCAP file. |
| `test_website.py` | The local HTTP test website provided by the instructor. |
| `FSCT8561_Operation_Sentinel_Traffic.pcap` | The synthetic network traffic file provided for packet analysis. |
| `requirement.txt` | Contains the Python libraries needed for the project. |
| `README_Students.txt` | Contains the instructor's instructions for the testing resources. |

## Setup and Installation

To get Operation Sentinel running, I first opened my Midterm folder in Visual Studio Code, where I kept all my Python files and the resources provided by the instructor. I made sure Python was installed and that I had the required libraries available.

I installed the libraries using the VS Code terminal with this command:

```powershell
py -m pip install -r requirement.txt
```

The main libraries I used were Scapy for analyzing network packets, pyotp for multi-factor authentication, and requests for HTTP security checking. I also used built-in Python libraries such as socket, hashlib, json, logging, and threading.

Once everything was installed, I used three separate terminals in VS Code to run the application.

### 1. Starting the Server

In the first terminal, I ran:

```powershell
py server.py
```

This starts the Operation Sentinel TCP server on 127.0.0.1 using port 9000. I kept the server running so the client could connect to it.

If I wanted to stop the server, I could type `exit` and press Enter.

### 2. Starting the Test Website

In the second terminal, I ran:

```powershell
py test_website.py
```

This starts the instructor-provided Northstar Demo Portal, which can be accessed at:

http://127.0.0.1:8765/

I used this website to test my TCP port scanner and HTTP security checker. The website was intentionally configured with missing security protections so I could identify them during testing.

### 3. Starting the Client

In the third terminal, I ran:

```powershell
py client.py
```

This connects the client to the server and brings up the login screen.

For my local testing, I used the following demonstration credentials:

- Username: `suraj`
- Password: `123`

After entering the correct username and password, the server asked for a six-digit TOTP code. For testing purposes, the current code was displayed in the server terminal.

Once I entered the correct TOTP code, I was able to access the main menu.

These credentials and the displayed TOTP code were only used for this local demonstration and would need to be changed for a real application.

## Using Operation Sentinel

After successfully logging in, the application displays the following menu:

```text
===== Operation Sentinel Menu =====
1. Analyze PCAP
2. Scan Local TCP Ports
3. Check HTTP Security
4. Logout
5. Exit
```

### Option 1 — Analyze PCAP

The first option allows me to analyze the PCAP file provided by the instructor. I used Scapy to read the packets and collect information such as the total number of packets, protocol counts, source IP addresses, and destination ports.

The analyzer also looks for possible suspicious network activity, such as a source contacting multiple destinations.

During my testing, the analyzer processed 123 packets, including 113 TCP packets and 10 UDP packets. It also identified 192.0.2.50 as a possible scanning source because it contacted 20 unique destinations.

### Option 2 — Scan Local TCP Ports

The second option allows me to scan a selected range of TCP ports using Python sockets.

When I select this option, the application asks me to enter a starting and ending port. It then attempts to connect to each port on 127.0.0.1 to determine which ports are open.

For example, I tested the following range:

- Starting port: 8760
- Ending port: 8770

When the instructor's website was running, the scanner identified port 8765 as open.

I also added input validation, a maximum scan range of 1,000 ports, and connection timeouts to prevent invalid scans and reduce the chance of the application hanging.

### Option 3 — Check HTTP Security

The third option allows me to check the instructor-provided Northstar Demo Portal for basic HTTP security issues using the requests library.

The checker examines four endpoints:

- `/`
- `/health`
- `/redirect`
- `/missing`

It checks HTTP response codes, redirects, missing security headers, and cookie security settings.

During my testing, the checker identified missing headers such as Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.

It also identified that the training_session cookie was missing HttpOnly, Secure, and SameSite attributes.

These findings show missing security protections, but they do not automatically mean that the website can be exploited.

### Option 4 — Logout

The fourth option allows the user to log out of the application. When selected, the server ends the authenticated session and disconnects the client.

### Option 5 — Exit

The fifth option closes the client application and ends its connection to the server.

## Testing the Application

After completing the application, I performed ten main test cases to make sure the different components worked correctly and handled errors properly. I also performed separate checks for invalid input and server disconnection.

| Test ID | Test Description |
|---|---|
| TC-01 | Successful username, password, and TOTP authentication |
| TC-02 | Failed password authentication |
| TC-03 | Unauthorized PCAP command rejection |
| TC-04 | Open TCP port detection |
| TC-05 | Closed TCP port detection |
| TC-06 | HTTP security findings |
| TC-07 | HTTP connection failure |
| TC-08 | PCAP summary analysis |
| TC-09 | PCAP suspicious traffic detection |
| TC-10A | Invalid port input |
| TC-10B | Server disconnection |

### Authentication Testing

For authentication testing, I entered the correct username and password followed by a valid TOTP code. The application successfully authenticated me and displayed the main menu.

I also tested an incorrect password to make sure the server rejected invalid credentials.

To test authorization, I used a separate Python test script to send an ANALYZE_PCAP command without logging in. The server returned an UNAUTHORIZED error, showing that PCAP analysis could not be requested without authentication.

### Port Scanner Testing

For the port scanner, I started the instructor's website and scanned ports 8760 through 8770. The scanner successfully detected port 8765 as open.

I also tested the scanner when the website was stopped and confirmed that port 8765 was no longer reported as open.

To test invalid input handling, I entered 9000 as the starting port and 8000 as the ending port. The application rejected the range and displayed an error message instead of performing the scan.

### HTTP Security Testing

For the HTTP checker, I started the local website and selected Option 3 from the main menu.

The checker successfully identified the response codes for all four endpoints, along with the missing security headers and cookie attributes.

I also stopped the website and ran the checker again. The application displayed connection errors for all four endpoints and returned to the main menu without crashing.

### PCAP Analysis Testing

For PCAP testing, I selected Option 1 after logging into the application.

The analyzer successfully processed the instructor-provided synthetic traffic file and displayed the packet summary.

It also identified possible TCP port scanning activity from 192.0.2.50, which contacted 20 unique destinations.

The PCAP file contains simulated traffic and is not a live capture of the local test website.

### Server Disconnection Testing

To test server disconnection, I stopped the TCP server while the client was still running.

I then attempted to perform PCAP analysis from the client menu.

The client detected that the connection was lost, displayed a connection error, and returned to the terminal without an unhandled Python traceback.

## Security Features

While developing Operation Sentinel, I added several security controls to make the application safer and handle common problems.

For authentication, I used password hashing and TOTP multi-factor authentication. This means the user must complete two authentication steps before accessing the main menu.

I also added server-side authorization for PCAP analysis so that unauthenticated clients cannot execute that protected command.

For port scanning, I restricted the target to localhost, limited the scan range, and used timeouts to prevent long connection attempts.

The HTTP checker is also restricted to the instructor's local website, while the PCAP analyzer only reads the provided offline traffic file.

I included error handling for invalid inputs, unavailable websites, and disconnected clients. The server also records security events using Python's logging library.

## Security Limitations

Although the application includes several security controls, there are still improvements I would need to make before using it in a real environment.

One limitation is that the TCP connection does not use TLS encryption. This means the data sent between the client and server is not encrypted, even though password hashing and TOTP authentication are implemented.

Another limitation is that the demonstration password is weak and the current TOTP code is displayed in the server terminal for testing.

The application also does not fully prevent TOTP replay attacks, and the authentication attempt limit can be bypassed by reconnecting.

The port scanner and HTTP checker run locally through the client menu, so they do not have the same server-side authorization protection as PCAP analysis.

If I were to improve the application for production, I would add TLS encryption, stronger password requirements, secure secret storage, better authentication rate limiting, and additional authorization checks.

## Scope and Safety

I developed and tested Operation Sentinel entirely within the authorized local environment provided for the midterm.

The TCP port scanner only scans 127.0.0.1, and the HTTP checker only accesses the instructor-provided Northstar Demo Portal.

For packet analysis, I used the synthetic PCAP file rather than collecting live network traffic.

I did not scan public websites, attempt to exploit vulnerabilities, generate malicious traffic, or collect real patient information.

The purpose of the application was to demonstrate the networking and security techniques learned in class while keeping the testing environment controlled and safe.

## Conclusion

Overall, Operation Sentinel allowed me to bring together the different concepts I learned throughout Labs 0–5 into one working Python application.

I was able to implement TCP client-server communication, password authentication, TOTP MFA, port scanning, HTTP security checking, and PCAP analysis.

Through testing, I confirmed that the application could perform its main functions and handle several invalid inputs and connection failures.

The project also helped me better understand why security controls such as encryption, authentication, authorization, and input validation are important when developing network applications.