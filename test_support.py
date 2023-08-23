def calculate_diffs(numbers):
    results = []
    for i in range(len(numbers) - 1):
        if all((numbers[i], numbers[i + 1])):
            results.append((numbers[i + 1] - numbers[i]) & 0xFFFFFFFF)
    return results

def calculate_rates(numbers, time):
    diffs = calculate_diffs(numbers)
    return [diff / time for diff in diffs]