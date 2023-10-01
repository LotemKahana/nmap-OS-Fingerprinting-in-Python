import sys
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
from parse_os_db import get_os_fingerprints_from_db
from constants import *

def find_os(fingerprint, number_of_os_match):
    """Find most matching operating systems for a fingerprint"""
    db = get_os_fingerprints_from_db()
    return match_fingerprint(fingerprint, db, number_of_os_match)

def match_os(os_fingerprint, db_fingerprint, weights):
    """score a fingerprint and os from db using weights
    score is in precentages"""
    result_match = dict()
    for testline in os_fingerprint.keys():
        result_match[testline] = match_test_line(os_fingerprint[testline], db_fingerprint[testline])
    score = score_match(result_match, weights)
    return (db_fingerprint["description"], score)
    

def match_test_line(test_line, db_line):
    """match a single test to a os fingerprint"""
    result = dict()
    for test_type in test_line.keys():
        if test_type in db_line.keys():
            result[test_type] = match_test(test_line[test_type], db_line[test_type])
        else:
            result[test_type] = False
    return result

def match_test(result, db_result):
    """match a single test, return True or False"""
    result_options = db_result.split(DB_SPLIT_OPTIONS)
    return any([match_test_option(result, result_option) for result_option in result_options])

def match_test_option(result, db_result):
    """most basic match between a fingerprint and an inner option in database
    return True or False"""
    if result == db_result:
        return True
    if not str(result).isnumeric():
        return False
    if DB_GREATER_THAN in db_result:
        return int(result) > int(db_result[1:], 16)
    if DB_LOWER_THAN in db_result:
        return int(result) < int(db_result[1:], 16)
    if DB_RANGE in db_result:
        lower, upper = db_result.split(DB_RANGE)
        return int(result) >= int(lower, 16) and int(result) <= int(upper, 16)
    return False

def score_match(match_map, weights):
    """score match using the matchmap and weights map.
    return a score between 0 and 100"""
    max_weight = 0
    test_accurecy = 0
    for test_line in match_map.keys():
        for test in match_map[test_line].keys():
            max_weight += int(weights[test_line][test])
            test_accurecy += int(weights[test_line][test]) * match_map[test_line][test]
    return int(test_accurecy / max_weight * 100)

def match_fingerprint(os_fingerprint, db, number_of_os_match):
    """find the most matching fingerprints from a db"""
    weights = db[0]
    scores = []
    for db_fingerprint in db[1:]:
        scores.append(match_os(os_fingerprint, db_fingerprint, weights))
    scores.sort(key=lambda a: a[1], reverse=True)
    return scores[:number_of_os_match]