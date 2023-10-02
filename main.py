import ctypes, os
import argparse

from port_scan.port_scan import get_oped_closed_ports
from os_detection.os_detect import get_os_info
from os_db.os_db import find_os


def parse_arguments():
    """argparser, thank you chat gpt for help"""
    # Create an ArgumentParser object
    parser = argparse.ArgumentParser(description="Scan open and closed ports on a destination IP.")

    # Add a required argument for the destination IP address
    parser.add_argument("destination_ip", help="The IP address of the destination host")

    # Add optional arguments for open and closed ports with short options
    parser.add_argument("-o", "--open-port", type=int, help="The open port to scan")
    parser.add_argument("-c", "--closed-port", type=int, help="The closed port to scan")

    # Add an option to specify the output file
    parser.add_argument("-f", "--output-file", help="Output file to write results")

    # Add an option to specify how many operating systems to match with a default of 3
    parser.add_argument(
        "-m", "--match-os", type=int, default=3, help="Number of operating systems to match (default: 3)"
    )

    # Parse the command-line arguments
    args = parser.parse_args()

    # Access the values of the arguments
    destination_ip = args.destination_ip
    open_port = args.open_port
    closed_port = args.closed_port
    output_file = args.output_file
    match_os = args.match_os
    return {"dst_ip": destination_ip, "open_port": open_port, "closed_port": closed_port, "output_file": output_file, "match_os": match_os}

def get_ports(open_port, closed_port, dst_ip):
    """et open and closed port, check if they were givven"""
    if open_port is None or closed_port is None:
        open_port, closed_port = get_oped_closed_ports(dst_ip)
    if open_port is not None:
        open_port = closed_port
    if closed_port is not None:
        open_port = closed_port
    return open_port, closed_port

def print_output(data, outfile):
    """print data output"""
    if outfile is not None:
        with open(outfile, "w") as f:
            for match in data:
                f.write(f"{match[0]}\nwith accurecy of {match[1]}%\n")
    else:
        for match in data:
            print(match[0], f"\nwith accurecy of {match[1]}%")

def is_admin():
    """check if program is running at high privileges on cross platform"""
    try:
        is_admin = os.getuid() == 0 # check for root, noteable program can run on lower priveleges but we will require root
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin

def main():
    arguments = parse_arguments()
    if not is_admin():
        print("please run code as admin/root")
    else:
        dst_ip = arguments["dst_ip"]
        open_port, closed_port = get_ports(arguments["open_port"], arguments["closed_port"], dst_ip)

        if open_port is None:
            print("could not find an open port.")
        if closed_port is None:
            print("could not find a closed port.")
        if open_port is not None and closed_port is not None:
            results = get_os_info(dst_ip, open_port, closed_port)
            number_of_os_match = arguments["match_os"]
            matches = find_os(results, number_of_os_match)
            print_output(matches, arguments["output_file"])

if __name__ == "__main__":
    main()