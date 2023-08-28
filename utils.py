import math
import zlib

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

def calculate_distance(udp_probes):
    return udp_probes[0].ttl - udp_probes[0].payload.ttl

def round_up_to_nearest(value, limit):
    next_power_of_2 = 2 ** math.ceil(math.log2(value))
    rounded_value = min(next_power_of_2, limit)
    return rounded_value

def r_test(probe):
    if probe:
        return "Y"
    return "N"

def df_test(probe):
    if probe.underlayer.flags.value & 2 != 2:
        return "Y"
    return "N"

def dfi_test(probes):
    first_flag = df_test(probes[0])
    secound_flag = df_test(probes[1])
    if first_flag == "N" and secound_flag == "N":
        return "N"
    if first_flag == "Y" and secound_flag == "Y":
        return "Y"
    if first_flag == "Y" and secound_flag == "N":
        return "S"
    return "O"

def t_test(ttl, u_packets):
    hops = calculate_distance(u_packets)
    return ttl + hops

def tg_test(ttl):
    return round_up_to_nearest(ttl, 255)

def cc_test(probe):
    ece_flag = probe.payload.flags.value & 128
    cwr_flag = probe.payload.flags.value & 64
    if ece_flag and not cwr_flag:
        return "Y"
    if not ece_flag and not cwr_flag:
        return "N"
    if ece_flag and cwr_flag:
        return "S"
    return "O"

def q_test(probe):
    result = ""
    if probe.reserved:
        result += "R"
    if probe.payload.urgptr & 32:
        result += "U"
    return result

def s_test(probe):
    seq = probe.payload.seq
    ack = probe.payload.ack
    if seq == 0:
        return "Z"
    if seq == ack:
        return "A"
    if seq == ack+1:
        return "A+"
    return "O"

def a_test(seq, probe):
    ack = probe.payload.ack
    if ack == 0:
        return "Z"
    if seq == ack:
        return "S"
    if (seq + 1) == ack:
        return "S+"
    return "O"

def f_test(probe):
    flags = probe.payload.flags.value
    result = ""
    if flags & 64:
        result += "E"
    if flags & 32:
        result += "U"
    if flags & 16:
        result += "A"
    if flags & 8:
        result += "P"
    if flags & 4:
        result += "R"
    if flags & 2:
        result += "S"
    if flags & 1:
        result += "F"
    return result

def w_test(probe):
    return probe.window

def rd_test(probe):
    if probe.flags.value & 4:
        data = probes["ecn"][0][0].payload.payload
        if not data:
            return zlib.crc32(data)
        return 0

def ipl_test(probe):
    return probe.len

def un_test(probe):
    return probe.payload.reserved

def ripl_test(probe):
    if probe.payload.len == 328:
        return "G"
    return probe.payload.len

def rid_test(probe, id):
    try:
        if probe.payload.payload.id == id:
            return "G"
        return probe.payload.payload.id
    except:
        return

def ripck_test(probe, chksum):
    if probe.chksum == 0:
        return "Z"
    if probe.chksum == chksum:
        return "I"
    return "G"
    
def ruck_test(probe, chksum):
    if probe.payload.payload.chksum == chksum:
        return "G"
    return probe.payload.payload.chksum

def rud_test(probe):
    if str(probe.payload.payload.payload.payload) == "b" + '\'' + "C" * 300 + '\'':
        return "G"
    return "I"

def cd_test(ie_1, ie_2):
    if ie_1.code == 0 and ie_2.code == 0:
        return "Z"
    if ie_1.code == 9 and ie_2.code == 0:
        return "S"
    if ie_1.code == ie_2.code:
        return ie_1.code
    return "O"