import utils
from response_extractor import extract_seq, extract_ops, extract_win # # special data extractors for tests with many probes

def init_tests(responces):
    """calculate the network distance to initiate the t test"""
    if responces["u"][0] is not None:
        utils.init_t_test(responces["u"])

def seq_test(probes):
    """conduct the seq tests"""
    test = dict()
    data = extract_seq(probes)
    if not any(data["sg_seq"]):
        return {"R": "N"}
    test["GCD"] = utils.gcd_test(data["sg_seq"])
    test["ISR"] = utils.isr_test(data["sg_seq"])
    test["SP"] = utils.sp_test(data["sg_seq"], test["GCD"])
    test["TI"] = utils.ti_test(data["sg_id"])
    test["CI"] = utils.ci_ii_test(data["t_closed_id"])
    test["II"] = utils.ci_ii_test(data["ie_id"])
    test["SS"] = utils.ss_test(data["ie_id"], data["t_id"], test["II"], test["TI"])
    test["TS"] = utils.ts_test(data["sg_ts"])
    for test_name in test.copy().keys():
        if test[test_name] is None:
            del test[test_name]
    return test

def ops_test(probes):
    """conduct the ops tests"""
    options_list = extract_ops(probes)
    if not any(options_list["sg_options"]):
        return {"R": "N"}
    option_string = [utils.o_test(option) for option in options_list["sg_options"]]
    option_numbers = ["O1", "O2", "O3", "O4", "O5", "O6"]
    return dict(zip(option_numbers, option_string))

def win_test(probes):
    """conduct the win tests"""
    window_sizes = extract_win(probes["sg"][0])["sg_windows"]
    if not any(window_sizes):
        return {"R": "N"}
    option_numbers = ["W1", "W2", "W3", "W4", "W5", "W6"]
    return dict(zip(option_numbers, window_sizes))

def ecn_test(probes):
    """conduct the ecn tests"""
    ecn_answer = probes["ecn"][0][0]
    test = dict()
    if ecn_answer is None:
        return test
    test["R"] = utils.r_test(ecn_answer)
    if test["R"] == "N":
        return test
    test["DF"] = utils.df_test(ecn_answer)
    test["T"] = utils.t_test(ecn_answer.ttl)
    if test["T"] is None:
        test["TG"] = utils.tg_test(ecn_answer.ttl)
        del test["T"]
    test["W"] = utils.w_test(ecn_answer)
    test["O"] = utils.o_test(ecn_answer.payload.options)
    test["CC"] = utils.cc_test(ecn_answer)
    test["Q"] = utils.q_test(ecn_answer)
    return test

def t_1_test(probes):
    """conduct the t1 test"""
    t_answer = probes["sg"][0][0]
    t_probe = probes["sg"][1][0]
    test = dict()
    test["R"] = utils.r_test(t_answer)
    if test["R"] == "N":
        return test
    test["DF"] = utils.df_test(t_answer)
    test["T"] = utils.t_test(t_answer.ttl)
    if test["T"] is None:
        test["TG"] = utils.tg_test(t_answer.ttl)
        del test["T"]
    test["S"] = utils.s_test(t_answer, t_probe)
    test["A"] = utils.a_test(t_probe.seq, t_answer)
    test["F"] = utils.f_test(t_answer)
    test["RD"] = utils.rd_test(t_answer)
    test["Q"] = utils.q_test(t_answer)
    return test

def t_i_test(probes, i):
    """conduct a general t test"""
    t_answer = probes["t"][0][i]
    t_probe = probes["t"][1][i]
    test = dict()
    test["R"] = utils.r_test(t_answer)
    if test["R"] == "N":
        return test
    test["DF"] = utils.df_test(t_answer)
    test["T"] = utils.t_test(t_answer.ttl)
    if test["T"] is None:
        test["TG"] = utils.tg_test(t_answer.ttl)
        del test["T"]
    test["W"] = utils.w_test(t_answer)
    test["S"] = utils.s_test(t_answer, t_probe)
    test["A"] = utils.a_test(t_probe.seq, t_answer)
    test["F"] = utils.f_test(t_answer)
    test["O"] = utils.o_test(t_answer.payload.options)
    test["RD"] = utils.rd_test(t_answer)
    test["Q"] = utils.q_test(t_answer)
    return test

def u1_test(probes):
    """conduct the u1 test"""
    u_answer = probes["u"][0]
    u_packet = probes["u"][1].__class__(bytes(probes["u"][1]))
    test = {"R": "Y"}
    if u_answer is None:
        return {"R": "N"}
    test["DF"] = utils.df_test(u_answer)
    test["T"] = utils.t_test(u_answer.ttl)
    if test["T"] is None:
        test["TG"] = utils.tg_test(u_answer.ttl)
        del test["T"]
    test["IPL"] = utils.ipl_test(u_answer)
    test["UN"] = utils.un_test(u_answer)
    test["RIPL"] = utils.ripl_test(u_answer)
    test["RID"] = utils.rid_test(u_answer, u_packet.id)
    test["RIPCK"] = utils.ripck_test(u_answer, u_packet.chksum)
    test["RUCK"] = utils.ruck_test(u_answer, u_packet.chksum)
    test["RUD"] = utils.rud_test(u_answer)
    return test

def ie_test(probes):
    """conduct the ie test"""
    ie_answer_first = probes["ie"][0][0]
    ie_answer_secound = probes["ie"][0][1]
    test = {"R": "Y"}
    if utils.r_test(ie_answer_first) == "N" or utils.r_test(ie_answer_secound) == "N":
        return {"R": "N"}
    test["DFI"] = utils.dfi_test((ie_answer_first, ie_answer_secound))
    test["T"] = utils.t_test(ie_answer_first.ttl)
    if test["T"] is None:
        test["TG"] = utils.tg_test(ie_answer_first.ttl)
        del test["T"]
    test["CD"] = utils.cd_test(ie_answer_first, ie_answer_secound)
    return test