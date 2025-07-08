#for personal use

# For any f..ked up situation who forces someone to use this Proxy Scanner

# 🌐 HTTP Proxy Scanner

![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Code Size](https://img.shields.io/github/languages/code-size/jeet8200/http-proxy-scanner)

An advanced asynchronous HTTP proxy scanner with multi-country support and comprehensive proxy verification.

## 🚀 Features

- **Multi-Protocol Support**: HTTP/HTTPS/SOCKS proxy detection
- **Asynchronous Scanning**: Fast concurrent checks (200+ threads)
- **Smart Verification**: 
  - Anonymity level detection (Transparent/Anonymous/Elite)
  - Response time measurement
  - Country/ISP identification
- **Multiple Output Formats**: 
  - Console display
  - SQLite database
  - Text file export
- **IP Range Management**: 
  - Automatic updates
  - Custom range support

## 📦 Installation

```bash
git clone https://github.com/jeet8200/http-proxy-scanner.git
cd http-proxy-scanner
pip install -r requirements.txt
## Installation
Windows Installation Guide for Proxy Scanner
1. Install Python

    Download Python from the official website
       https://www.python.org/downloads/windows/

        Check "Add Python to PATH" during installation

        Click "Install Now"

    Verify installation:

        Open Command Prompt (Win+R → type cmd)

        Run:
        cmd

        python --version

        You should see Python 3.x.x

3. Install Required Dependencies

    Open Command Prompt as Administrator

    Install pip packages:
    cmd

         pip install aiohttp sqlite3 ipaddress requests colorama


5. Prepare IP Ranges File

    Create ipranges.txt in the same folder

    Add Iranian IP ranges (for other places change the code ) - (one per line), for example:
    text

    5.52.0.0/14
    5.57.32.0/21
    5.61.24.0/23

6. Run the Scanner
cmd

http-proxy-scanner.py

6. First Run Setup

The program will automatically create:

    proxies.db (SQLite database)

    open_proxies.txt (found proxies)

    working_proxies.txt (verified proxies)

    working_ranges.txt (productive IP ranges)

#THINGS TO KNOW BEFOR USEING

Ethical and Legal Considerations

    Intended Use:
    The script is designed to scan for open HTTP proxies, especially in Iranian IP ranges.
    Note: Scanning IP ranges you do not own or have explicit permission to scan may violate laws or terms of service in many regions.
    You are responsible for ensuring your usage is legal and ethical.
    Network Load:
    With a default of 200 concurrent connections, this script can generate significant network traffic.
    Be careful: Running large-scale scans may trigger abuse detection or get your IP blacklisted.
