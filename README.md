# nmap-OS-Fingerprinting-in-Python

Nmap is a powerfull well known program for network scanning.
Please refer to [nmap.org](https://nmap.org/download.html) for full documentation

## Overview

This project is a Python implementation of Nmap's OS fingerprinting functionality. It is designed for educational purposes to help you understand how Nmap's OS fingerprinting works and how to use it in your own projects. 

### Installation Steps

Before you begin, ensure you have met the following requirements:

- [Python](https://www.python.org/) 3.9 or higher
- [Scapy](https://scapy.net/) library for Python (used for packet analysis)
- [PyInstaller](https://www.pyinstaller.org/) (for creating standalone executables)

Follow these steps to set up and run the Nmap OS fingerprinting tool:

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/nmap-os-fingerprinting.git
   cd nmap-os-fingerprinting
    ```
2. Install requirments:

    [Install python](https://www.python.org/) version 3.9 or higher
    ```bash
    pip install -r requirements.txt
    ```
3. Install program:

    Linux:
    ```bash
    ./install.sh
    ```
    If you want to specify a custom installation directory, you can use the -d or --dir option followed by the desired directory path:

    ```bash
    ./install.sh -d /path/to/custom_directory
    ```

## Usage: os_detect

### <span style="color:purple">Positional Arguments</span>

- <span style="color:orange">destination_ip</span>: The IP address of the destination host

### <span style="color:purple">Options</span>

- <span style="color:orange">-h, --help</span>: Show this help message and exit
- <span style="color:orange">-o OPEN_PORT, --open-port OPEN_PORT</span>: Specify the open port to scan
- <span style="color:orange">-c CLOSED_PORT, --closed-port CLOSED_PORT</span>: Specify the closed port to scan
- <span style="color:orange">-f OUTPUT_FILE, --output-file OUTPUT_FILE</span>: Specify the output file to write results
- <span style="color:orange">-m MATCH_OS, --match-os MATCH_OS</span>: Specify the number of operating systems to match (default: 3)