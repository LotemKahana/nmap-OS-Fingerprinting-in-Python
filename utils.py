def generate_option_string(options):
    if options is None:
        return

    option_string = ""
    for option, argument in options:
        if option == 'EOL':
            option_string += 'L'
        elif option == 'NOP':
            option_string += 'N'
        elif option == 'MSS':
            option_string += 'M' + format(argument, 'X')
        elif option == 'WScale':
            option_string += 'W' + str(argument)
        elif option == 'Timestamp':
            tsval, tsecr = argument
            tsval_char = '1' if tsval != 0 else '0'
            tsecr_char = '1' if tsecr != 0 else '0'
            option_string += 'T' + tsval_char + tsecr_char
        elif option == 'SAckOK':
            option_string += 'S'
        else:
            raise
    return option_string

def r_test(probe):
    return probe

def df_test(probe):
    return probe.underlayer.flags.value & 2 != 2