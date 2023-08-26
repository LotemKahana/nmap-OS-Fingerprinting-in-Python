import utils
from seq_tests import *
from response_extractor import extract_seq, extract_ops, extract_win
def seq_test(probes):
    data = extract_seq(probes)
    gcd = gcd_test(data["sg_syn"])
    isr = isr_test(data["sg_syn"])
    sp = sp_test(data["sg_syn"], gcd)
    
    ti = ti_test(data["sg_id"])
    ci = ci_test(data["t_closed_id"])
    ii = ii_test(data["ie_id"])
    ss = ss_test(data["ie_id"], data["t_id"], ii, ti)
    ts = ts_test(data["sg_ts"])
    return {"gcd":gcd, "isr":isr, "sp":sp, "ti":ti, "ci":ci, "ii":ii, "ss":ss, "ts":ts}

def ops_test(probes):
    options_list = extract_ops(probes)
    option_string = [utils.generate_option_string(option) for option in options_list["sg_options"]]
    option_numbers = ["01", "02", "03", "04", "05", "06"]
    return dict(zip(option_numbers, option_string))

def win_test(probes):
    window_sizes = extract_win(probes)["sg_windows"]
    option_numbers = ["01", "02", "03", "04", "05", "06"]
    return dict(zip(option_numbers, window_sizes))

def ecn_test(probes):
    ecn_answer = probes["ecn_response"]
    test = dict()
    test["R"] = utils.r_test(ecn_answer)
    if test["R"] == "N":
        return test
    ecn_answer = ecn_answer[0] # strip list
    test["DF"] = utils.df_test(ecn_answer)
    test["T"] = utils.t_test(ecn_answer.ttl, probes["u_responses"])
    test["TG"] = utils.tg_test(ecn_answer.ttl)
    test["CC"] = utils.cc_test(ecn_answer)
    test["Q"] = utils.q_test(ecn_answer)