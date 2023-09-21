import math
import zlib
from constants import *

def o_test(options):
    """Create a string to represent the tcp options field"""
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

def round_up_to_nearest(value, limit=None):
    """round up to nearest power of 2 up to limit (optional)"""
    next_power_of_2 = 2 ** math.ceil(math.log2(value))
    if limit is not None:
        rounded_value = min(next_power_of_2, limit)
    return rounded_value

def r_test(packet):
    """Tests if a packet exists"""
    if packet is not None:
        return "Y"
    return "N"

def df_test(packet):
    """Test for existance of DF flag in a IP packet"""
    if packet.underlayer.flags.value & IP_DF_FLAG != IP_DF_FLAG:
        return "Y"
    return "N"

def dfi_test(probes):
    """Conduct the dfi test on testing for the DF flag on 2 packets"""
    first_flag = df_test(probes[0])
    secound_flag = df_test(probes[1])
    if first_flag == "N" and secound_flag == "N":
        return "N"
    if first_flag == "Y" and secound_flag == "Y":
        return "Y"
    if first_flag == "Y" and secound_flag == "N":
        return "S"
    return "O"

def init_t_test(udp_probes):
    """init the t_test function to use the number of hopes calculated from the icmp responce"""
    t_test(64, init=(udp_probes.ttl - udp_probes.payload.ttl))

def t_test(ttl, hops=[0], init=0):
    "Conduct the t test, have to be initiated first to keep hops"
    if init != 0:
        hops[0] = init
        return
    return ttl + hops[0]

def tg_test(ttl):
    """try and guess the ttl based on popular implementations"""
    return round_up_to_nearest(ttl, MAX_TTL)

def cc_test(probe):
    """"""
    ece_flag = probe.payload.flags.value & TCP_ECE_FLAG
    cwr_flag = probe.payload.flags.value & TCP_CWR_FLAG
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
    if probe.payload.urgptr & TCP_URG_FLAG:
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
    if flags & TCP_ECE_FLAG:
        result += "E"
    if flags & TCP_URG_FLAG:
        result += "U"
    if flags & TCP_ACK_FLAG:
        result += "A"
    if flags & TCP_PSH_FLAG:
        result += "P"
    if flags & TCP_RST_FLAG:
        result += "R"
    if flags & TCP_SYN_FLAG:
        result += "S"
    if flags & TCP_FIN_FLAG:
        result += "F"
    return result

def w_test(probe):
    return probe.window

def rd_test(probe):
    if probe.flags.value & TCP_RST_FLAG:
        data = probes["ecn"][0][0].payload.payload
        if not data:
            return zlib.crc32(data)
        return 0

def ipl_test(probe):
    return probe.len

def un_test(probe):
    return probe.payload.reserved

def ripl_test(probe):
    if probe.payload.len == BASIC_UDP_HEADER_LENGTH:
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