import os
from pathlib import Path
from constants import *
import re

def get_os_db_data():
    """Read the db file"""
    parent_dir = Path(os.path.dirname(os.path.realpath(__file__)))
    nmap_db_path = os.path.join(str(parent_dir), NMAP_DB_FILE)
    nmap_db_path = os.path.join(EXTERNAL_FILES_DICT, NMAP_DB_FILE)
    with open(nmap_db_path) as os_db:
        data = os_db.read().splitlines()
    return data

def split_to_os(os_db):
    """split the db file to different os"""
    chunk = []
    finger_prints = []
    for line in os_db:
        if len(line) == 0:
            finger_prints.append(chunk)
            chunk = []
        elif line[0] != DB_COMMENT_CHAR:
            chunk.append(line)
    return finger_prints

def parse_test_line(test_line):
    """parse a single test line,
    return a dictinary of testline's name and the data in a dictionary of \"testname: result \" format"""
    tests = re.findall(r'(\w+)=(.*?)[%)]', test_line)
    headline = re.search(r"^\w+", test_line).group()
    data = dict()
    for test in tests:
        test, options = test
        data[test] = options
    return {headline: data}

def parse_fingerprints(prints):
    """convert a list of unparsed fingerprints to a list of parsed fingerprints"""
    test_list = []
    for os_data in prints:
        if len(os_data) != 0:
            os_description = "\n".join(os_data[:len(os_data) - NUMBER_OF_TESTS])
            full_test = {"description": os_description}
            for test_line in os_data[-NUMBER_OF_TESTS:]:
                full_test.update(parse_test_line(test_line))
            test_list.append(full_test)
    return test_list

def get_os_fingerprints_from_db():
    """get a list of parsed fingerprints from the imbedded db"""
    data = get_os_db_data()
    data = split_to_os(data)
    return parse_fingerprints(data)