import itertools
import os
import time
import shutil
import random
from threading import Timer
from subprocess import Popen, PIPE
from multiprocessing import Process

class Setting:
    def __init__(self):
        #self.rootpath = "D:/Work/proverif2.01/FIDO/"
        self.rootpath = "D:/me/proverif2.01/FIDO/"
        self.querypath = self.rootpath + "query.pv"
        self.temppath = self.rootpath + "temp.pv"
        self.regpath = self.rootpath + "reg.pv"
        self.authpath = self.rootpath + "auth.pv"
        self.logpath = self.rootpath + "analysis.log"
        self.templibpath = self.rootpath + "templib.pvl"
        self.resultpath = self.rootpath + "result/"
class RUN:
    def __init__(self):
        self.setting = Setting()
        self.done = False
    def set_phase(self,p):
        self.phase = p
        if p == "reg":
            self.type_set_row = 3 # indicate type
            self.insert_row = 19  # insert line number
        else:
            self.type_set_row = 4 # indicate type
            self.insert_row = 31  # insert line number
    def set_type(self,t):
        self.type = t
    def set_query(self,q):
        self.query = q
    def set_compfields(self,comp):
        self.comp_field = comp
        self.comp_nums = len(comp)
    def set_malientities(self,mali):
        self.mali_ent = mali
        self.mali_nums = len(mali)
    def if_all_set(self):
        return self.type and self.query and self.comp_field and self.mali_ent and self.phase
    def write_file(self): #write tempfile to analyse
        assert self.if_all_set()
        if self.phase == "reg":
            f1 = open(self.setting.regpath, "r")
        elif self.phase == "auth_1br" or self.phase == "autr_2br":
            f1 = open(self.setting.authpath,"r")
        elif self.phase == "reg_unlink"
            f1 = open(self.setting.regunlinkpath,"r")
        elif self.phase == "auth_unlink"
            f1 = open(self.setting.authunlinkpath, "r")
        f2 = open(self.setting.querypath,"w")
        f1lines = f1.readlines()
        f2.writelines(self.query[1])
        for i in range(len(f1lines)):
            if i == self.type_set_row:
                f2.writelines(self.type[1])
            if i == self.insert_row:
                f2.writelines(self.comp_field[1])
                f2.writelines(self.mali_ent[1])
            f2.writelines(f1lines[i])
        f1.close()
        f2.close()
'''
A combination class
Input a 4 dimension vectors {
    types: a dict indicate all possible types of the authenticator
    queries: a dict for all queries
    outlines: a dict for all fields be compromised
    entities: a dict for all exsist malicious situation
}
Output a class RUN for verify
'''
class Comb:
    def __init__(self,case):
        self.phase = case.phase
        self.types = case.types
        self.queries = case.queries
        self.comp_fields = case.comp_fields
        self.entities = case.mali_entities
        self.t_nums = len(self.types)
        self.q_nums = len(self.queries)
        self.c_nums = len(self.comp_fields)
        self.e_nums = len(self.entities)
        self.cur_t = 0
        self.cur_c = 0
        self.cur_e = 0
        self.cur_q = -1
    def get_combine(self):
        if self.cur_c == self.c_nums - 1:
            self.cur_c = 0
            if(self.cur_e == self.e_nums - 1):
                self.cur_e = 0
                if(self.cur_q == self.q_nums - 1):
                    self.cur_q = 0
                    if(self.cur_t == self.t_nums - 1):
                        run = RUN()
                        run.done = True
                        return run
                    else:
                        self.cur_t = self.cur_t + 1
                else:
                    self.cur_q = self.cur_q + 1
            else:
                self.cur_e = self.cur_e + 1
        else:
            self.cur_c = self.cur_c + 1
        run = RUN()
        run.set_phase(self.phase)
        run.set_type(self.types[self.cur_t])
        run.set_compfields(self.comp_fields[self.cur_c])
        run.set_malientities(self.entities[self.cur_e])
        run.set_query(self.queries[self.cur_q])
        return run

'''
when indicate a specific authenticator type,
this class gives all posssible cases of 4 dinemtion vectors
'''
class Case:
    def __init__(self,phase):
        self.phase = phase
        if(phase == "reg"):
            self.types = []
            self.types.append(("autr_1b","let atype = autr_1b in\n"))
            self.types.append(("autr_2b", "let atype = autr_2b in\n"))
            self.types.append(("autr_1r", "let atype = autr_1r in\n"))
            self.types.append(("autr_2r", "let atype = autr_2r in\n"))
            self.queries = []
            self.queries.append(('RS-ak', "query secret testak.\n"))
            self.queries.append(("RS-cntr","query secret cntr.\n"))
            self.queries.append(("RS-skau", "query secret skAU.\n"))
            self.queries.append(("Rauth","query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_reg(u,a,aa,kid)) ==> (inj-event(Autr_verify_reg(u,a,aa,kid))==> inj-event(UA_init_reg(u,a))).\n"))
            temp_out_fields = ["out(c,skAT);\n", "out(c,token);\n", "out(c,wrapkey);\n"]
            temp_entities = []
            temp_entities.append("RegUC(c, MC, fakefacetid)|\n")
            temp_entities.append("RegUA(https, c, uname,appid,password)|\n")
            temp_entities.append("RegASM(c, AM, token, fakecallerid, atype)|\n")
            temp_entities.append("RegUC(CU, c, facetid)|\n")
            temp_entities.append("RegAutr(c, aaid, skAT, wrapkey, atype)|\n")
            temp_entities.append("RegASM(MC, c, token, callerid, atype)|\n")
        elif phase == "auth_1br":
            self.types = []
            self.types.append(("autr_1b_em","let atype = autr_1b in\n let ltype = empty in"))
            self.types.append(("autr_1b_st","let atype = autr_1b in\n let ltype = stepup in"))
            self.types.append(("autr_1r_em","let atpye = autr_1r in\n let ltype = empty in"))
            self.types.append(("autr_1r_st","let atpye = autr_1r in\n let ltype = stepup in"))
            self.queries = []
            self.queries.append(("AS-ak","query secret testak.\n"))
            self.queries.append(("AS-cntr","query secret cntr.\n"))
            self.queries.append(("AS-skau","query secret skAU.\n"))
            self.queries.append(("AS-tr","query secret tr.\n"))
            self.queries.append(("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> inj-event(Autr_verify_auth_1br(u,a,aa,kid)).\n"))
            self.queries.append(("auth-tr","query tr:Tr; inj-event(RP_success_tr(tr)) ==> inj-event(Autr_verify_tr(tr)).\n"))
            temp_out_fields = ["out(c,skAU);\n", "out(c,token);\n", "out(c,wrapkey);\n", "out(c,cntr);\n"]
            temp_entities = []
            temp_entities.append("AuthUC(c, MC, fakefacetid, ltype)|\n")
            temp_entities.append("AuthUA(https, c, uname, ltype)|\n")
            temp_entities.append("AuthASM(c,AM,token,fakecallerid,atype,ltype)|\n")
            temp_entities.append("AuthUC(CU, c, facetid, ltype)|\n")
            temp_entities.append("AuthAutr(c,aaid,wrapkey,cntr,atype,ltype)|\n")
            temp_entities.append("AuthASM(MC,c,token,callerid,atype,ltype)|\n")
        elif phase == "auth_2br":
            self.types = []
            self.types.append(("autr_2b","let atype = autr_2b in\n let ltype = stepup in"))
            self.types.append(("autr_2r","let atype = autr_2r in\n let ltype = stepup in"))
            self.queries = []
            self.queries.append(("AS-ak", "query secret testak.\n"))
            self.queries.append(("AS-cntr", "query secret cntr.\n"))
            self.queries.append(("AS-skau", "query secret skAU.\n"))
            self.queries.append(("AS-tr", "query secret tr.\n"))
            self.queries.append(("Aauth-2br","query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> inj-event(Autr_verify_auth_2br(a,aa,kid)).\n"))
            self.queries.append(("auth-tr", "query tr:Tr; inj-event(RP_success_tr(tr)) ==> inj-event(Autr_verify_tr(tr)).\n"))
            temp_out_fields = ["out(c,skAU);\n", "out(c,token);\n", "out(c,wrapkey);\n", "out(c,cntr);\n"]
            temp_entities = []
            temp_entities.append("AuthUC(c, MC, fakefacetid, ltype)|\n")
            temp_entities.append("AuthUA(https, c, uname, ltype)|\n")
            temp_entities.append("AuthASM(c,AM,token,fakecallerid,atype,ltype)|\n")
            temp_entities.append("AuthUC(CU, c, facetid, ltype)|\n")
            temp_entities.append("AuthAutr(c,aaid,wrapkey,cntr,atype,ltype)|\n")
            temp_entities.append("AuthASM(MC,c,token,callerid,atype,ltype)|\n")
        else phase == "reg_unlink":
            self.types = []
            self.types.append(("autr_1b","let atype = autr_1b in\n"))
            self.types.append(("autr_2b", "let atype = autr_2b in\n"))
            self.types.append(("autr_1r", "let atype = autr_1r in\n"))
            self.types.append(("autr_2r", "let atype = autr_2r in\n"))
            self.queries = [("no-query","(*Observational equivalence uses no query*)")]
            temp_out_fields = ["out(c,skAT);\n", "out(c,token);\n", "out(c,wrapkey);\n"]
            temp_entities = []
            temp_entities.append("RegUC(c, MC, fakefacetid)|\n")
            temp_entities.append("RegUA(https, c, uname,appid,password)|\n")
            temp_entities.append("RegASM(c, AM, token, fakecallerid, atype)|\n")
            temp_entities.append("RegUC(CU, c, facetid)|\n")
            temp_entities.append("RegAutr(c, aaid, skAT, wrapkey, atype)|\n")
            temp_entities.append("RegASM(MC, c, token, callerid, atype)|\n")
        else phase == "auth_unlink":
            self.types = []
            self.types.append(("autr_1b_em","let atype = autr_1b in\n let ltype = empty in"))
            self.types.append(("autr_1b_st","let atype = autr_1b in\n let ltype = stepup in"))
            self.types.append(("autr_1r_em","let atpye = autr_1r in\n let ltype = empty in"))
            self.types.append(("autr_1r_st","let atpye = autr_1r in\n let ltype = stepup in"))
            self.queries = [("no-query","(*Observational equivalence uses no query*)")]
            temp_out_fields = ["out(c,skAU);\n", "out(c,token);\n", "out(c,wrapkey);\n", "out(c,cntr);\n"]
            temp_entities = []
            temp_entities.append("AuthUC(c, MC, fakefacetid, ltype)|\n")
            temp_entities.append("AuthUA(https, c, uname, ltype)|\n")
            temp_entities.append("AuthASM(c,AM,token,fakecallerid,atype,ltype)|\n")
            temp_entities.append("AuthUC(CU, c, facetid, ltype)|\n")
            temp_entities.append("AuthAutr(c,aaid,wrapkey,cntr,atype,ltype)|\n")
            temp_entities.append("AuthASM(MC,c,token,callerid,atype,ltype)|\n")
        else:
            print("use the correct params to initiate the class Case!")
        self.comp_fields = []
        for delnum in range(len(temp_out_fields)+ 1) :
            for pre in itertools.combinations(temp_out_fields, delnum):
                tmp_str = ""
                for sr in pre:
                    tmp_str += sr
                self.comp_fields.append((str(len(pre)), tmp_str))
        self.mali_entities = []
        for i in range(len(temp_entities)):  
            tmp_str = ""
            for j in range(i):
                tmp_str += temp_entities[j]
            self.mali_entities.append((str(i), tmp_str))

def make_temp_lib(phase):
    setting = Setting()
    f1 = open(setting.rootpath+'FIDO.pvl', 'r')
    f2 = open(setting.rootpath+'templib.pvl', 'w')
    all = f1.readlines()
    f2.writelines(all)
    f1.close()
    f2.close()
    if phase == "reg":
        shutil.rmtree(setting.resultpath + "/reg", True)
    elif phase == "auth_1br":
        shutil.rmtree(setting.resultpath + "/auth_1br", True)
    else:
        shutil.rmtree(setting.resultpath + "/auth_2br", True)


"""
"""
def analysis(phase):
    make_temp_lib(phase)
    setting = Setting()
    case = Case(phase)
    comb = Comb(case)
    log = open(setting.logpath, mode='a', encoding='utf-8')
    count = 1
    while True:
        run = comb.get_combine()
        if run.done == True:
            break
        run.write_file()
        ret, result = proverif(run)
        msg = str(count).ljust(4)
        if ret == "false":  # there exist attack
            msg += " false"
        elif ret == "true":
            msg += " turee"
        else:
            msg += " whatt"
        msg += " type-"
        msg += run.type[0].ljust(8)
        msg += " query-"
        msg += run.query[0].ljust(8)
        msg += " malie-"
        msg += run.mali_ent[0].ljust(2)
        msg += " compf-"
        msg += run.comp_field[0].ljust(2)
        print(msg)
        count = count + 1
        if ret == "true":
            continue
        if not os.path.exists(setting.resultpath + run.phase + "/" + run.type[0] + "/" + run.query[0]):
            os.makedirs(setting.resultpath + run.phase + "/" + run.type[0] + "/" + run.query[0])
        f = open(setting.resultpath + run.phase + "/" + run.type[0] + "/" + run.query[0]  + "/" + msg, "w")
        f2 = open(setting.querypath, "r")
        f.writelines(f2.readlines())
        f.writelines(str(result[-1000:-1]))
        f.close()
        f2.close()
    log.close()

def proverif(run):
    setting = Setting()
    output = Popen('proverif -lib "' + setting.templibpath + '" ' + setting.querypath, stdout=PIPE, stderr=PIPE)
    timer = Timer(60, lambda process: process.kill(), [output])
    try:
        timer.start()
        stdout, stderr = output.communicate()
        return_code = output.returncode
    finally:
        timer.cancel()
    result = stdout
    if (result[-400:-1].find(b'error') != -1):
        ret = 'error'
    elif (result[-600:-1].find(b'false') != -1):
        ret = 'false'
    elif (result[-2000:-1].find(b'hypothesis:') != -1):
        ret = 'trace'
    elif (result[-400:-1].find(b'prove') != -1):
        ret = 'prove'
    elif (result[-400:-1].find(b'true') != -1):
        ret = 'true'
    else:
        ret = 'tout'
    return ret, result

analysis("reg")
analysis("auth_1br")
analysis("auth_2br")