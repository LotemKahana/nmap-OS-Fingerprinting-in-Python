import sys
from pathlib import Path
base_dir = Path(__file__).parent.parent
sys.path.append(str(base_dir))
from os_db.os_db import get_os_fingerprints_from_db
from os_db.os_db import find_os
from random import choice, randint

db = get_os_fingerprints_from_db()

fingerprint = choice(db)
expected_result = fingerprint["description"]
del fingerprint["description"]

for line_name in fingerprint.keys():
    testline = fingerprint[line_name]
    for test_name in testline.keys():
        test = testline[test_name].split("|")
        test = choice(test)
        if "-" in test:
            first, secound = test.split("-")
            test = choice(range(int(first, 16), int(secound, 16) + 1))
        elif ">" in test:
            test = int(test[1:], 16) + randint(1, 100)
        elif "<" in test:
            test = int(test[1:], 16) - randint(1, int(test[1:], 16))
        testline[test_name] = test

a = find_os(fingerprint)
if a[0][1] == 100:
    print("yes")
else:
    print(f"erorr comparing th following description:\n{fingerprint}")