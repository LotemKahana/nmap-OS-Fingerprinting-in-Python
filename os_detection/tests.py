import utils
from seq_tests import *
from response_extractor import extract_seq, extract_ops, extract_win

def init_tests(responces):
    if responces["u"][0] is not None:
        utils.init_t_test(responces["u"][0])


def seq_test(probes):
    test = dict()
    data = extract_seq(probes)
    if not any(data["sg_syn"]):
        return test
    test["gcd"] = gcd_test(data["sg_syn"])
    test["isr"] = isr_test(data["sg_syn"])
    test["sp"] = sp_test(data["sg_syn"], test["gcd"])
    test["ti"] = ti_test(data["sg_id"])
    test["ci"] = ci_test(data["t_closed_id"])
    test["ii"] = ii_test(data["ie_id"])
    test["ss"] = ss_test(data["ie_id"], data["t_id"], test["ii"], test["ti"])
    test["ts"] = ts_test(data["sg_ts"])
    return test

def ops_test(probes):
    options_list = extract_ops(probes)
    option_string = [utils.o_test(option) for option in options_list["sg_options"]]
    option_numbers = ["01", "02", "03", "04", "05", "06"]
    return dict(zip(option_numbers, option_string))

def win_test(probes):
    window_sizes = extract_win(probes["sg"][0])["sg_windows"]
    option_numbers = ["01", "02", "03", "04", "05", "06"]
    return dict(zip(option_numbers, window_sizes))

def ecn_test(probes):
    ecn_answer = probes["ecn"][0]
    test = dict()
    if ecn_answer is None:
        return test
    test["R"] = utils.r_test(ecn_answer)
    if test["R"] == "N":
        return test
    ecn_answer = ecn_answer[0] # strip list
    test["DF"] = utils.df_test(ecn_answer)
    test["T"] = utils.t_test(ecn_answer.ttl)
    test["TG"] = utils.tg_test(ecn_answer.ttl)
    test["W"] = utils.w_test(ecn_answer)
    test["O"] = utils.o_test(ecn_answer.payload.options)
    test["CC"] = utils.cc_test(ecn_answer)
    test["Q"] = utils.q_test(ecn_answer)
    return test

def t_1_test(probes):
    t_answer = probes["sg"][0][0]
    t_probe = probes["sg"][1][0]
    test = dict()
    test["R"] = utils.r_test(t_answer)
    if test["R"] == "N":
        return test
    test["DF"] = utils.df_test(t_answer)
    test["T"] = utils.t_test(t_answer.ttl)
    test["TG"] = utils.tg_test(t_answer.ttl)
    test["S"] = utils.s_test(t_answer)
    test["A"] = utils.a_test(t_probe.seq, t_answer)
    test["F"] = utils.f_test(t_answer)
    test["RD"] = utils.rd_test(t_answer)
    test["Q"] = utils.q_test(t_answer)
    return test

def t_i_test(probes, i):
    t_answer = probes["t"][0][i]
    t_probe = probes["t"][1][i]
    test = dict()
    test["R"] = utils.r_test(t_answer)
    if test["R"] == "N":
        return test
    test["DF"] = utils.df_test(t_answer)
    test["T"] = utils.t_test(t_answer.ttl)
    test["TG"] = utils.tg_test(t_answer.ttl)
    test["S"] = utils.s_test(t_answer)
    test["A"] = utils.a_test(t_probe.seq, t_answer)
    test["F"] = utils.f_test(t_answer)
    test["RD"] = utils.rd_test(t_answer)
    test["Q"] = utils.q_test(t_answer)
    test["W"] = utils.w_test(t_answer)
    return test

def u1_test(probes):
    u_answer = probes["u"][0]
    u_packet = probes["u"][1].__class__(bytes(probes["u"][1]))
    test = dict()
    test["DF"] = utils.df_test(u_answer)
    test["T"] = utils.t_test(u_answer.ttl)
    test["TG"] = utils.tg_test(u_answer.ttl)
    test["IPL"] = utils.ipl_test(u_answer)
    test["UN"] = utils.un_test(u_answer)
    test["RIPL"] = utils.ripl_test(u_answer)
    test["RID"] = utils.rid_test(u_answer, u_packet.id)
    test["RIPCK"] = utils.ripck_test(u_answer, u_packet.chksum)
    test["RUCK"] = utils.ruck_test(u_answer, u_packet.chksum)
    test["RUD"] = utils.rud_test(u_answer)
    return test

def ie_test(probes):
    ie_answer_first = probes["ie"][0][0]
    ie_answer_secound = probes["ie"][0][1]
    test = dict()
    
    if utils.r_test(ie_answer_first) == "N" or utils.r_test(ie_answer_secound) == "N":
        test["R"] = "N"
        return test
    test["R"] = "Y"
    test["DFI"] = utils.dfi_test((ie_answer_first, ie_answer_secound))
    test["T"] = utils.t_test(ie_answer_first.ttl)
    test["TG"] = utils.tg_test(ie_answer_first.ttl)
    test["CD"] = utils.cd_test(ie_answer_first, ie_answer_secound)
    return test