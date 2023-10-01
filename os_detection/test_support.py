def calculate_diffs(numbers):
    """calculate the mod distance between the objects in a list under 2^32 field"""
    results = []
    for i in range(len(numbers) - 1):
        if all((numbers[i], numbers[i + 1])):
            results.append(min((numbers[i + 1] - numbers[i]) & 0xFFFFFFFF, (numbers[i] - numbers[i + 1]) & 0xFFFFFFFF))
    return results

def calculate_rates(numbers, time):
    """calculate rated based on the differences and time"""
    diffs = calculate_diffs(numbers)
    return [diff / time for diff in diffs]

def filter_none_probes(unfiltered_list):
    """filter out None objects in a list"""
    return [element for element in unfiltered_list if element is not None]

def sequence_test(id_list):
    """conduct tests on a list of ids"""
    if all(id_num == 0 for id_num in id_list):
        return 'Z'
    
    if len(set(id_list)) == 1:
        return hex(id_list[0])
    
    diffs = []
    for i in range(len(id_list) - 1):
        diffs.append((id_list[i+1] - id_list[i]) % (2 ** 32 - 1))
    
    if (max(diffs) > 20000 and len(id_list) > 2):
        return "RD"
    
    # Check if any difference between two consecutive IDs exceeds 1,000 and is not evenly divisible by 256
    if any(abs(id_list[i] - id_list[i + 1]) > 1000 and (id_list[i] - id_list[i + 1]) % 256 != 0 for i in range(len(id_list) - 1)):
        return 'RI'

    # Check if all differences are divisible by 256 and no greater than 5,120
    if all(diff % 256 == 0 and diff <= 5120 for diff in (id_list[i] - id_list[i + 1] for i in range(len(id_list) - 1))):
        return 'BI'

    # Check if all differences are less than ten
    if all(abs(id_list[i] - id_list[i + 1]) < 10 for i in range(len(id_list) - 1)):
        return 'I'

    # If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint
    return None
