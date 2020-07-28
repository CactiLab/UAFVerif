import itertools
import os
import sys
import operator
import threading
import time
import shutil
import random
from threading import Timer
from subprocess import Popen, PIPE
from multiprocessing import Process

# general setting
class Setting:
   # rootpath = "D:/Work/proverif2.01/FIDO/"
    rootpath = "D:/me/proverif2.01/FIDO/"
    #querypath = rootpath + "query.pv"
    reg_set_type_row = 13
    reg_insert_row = 17
    auth_set_type_row = 7
    auth_insert_row = 24
    regpath = rootpath + "reg.pv"
    authpath = rootpath + "auth.pv"
    logpath1 = rootpath + "analysis1.log"
    logpath2 = rootpath + "analysis2.log"
    logpath3 = rootpath + "analysis3.log"
    logpath4 = rootpath + "analysis4.log"
    logpath5 = rootpath + "analysis5.log"
    logpath6 = rootpath + "analysis6.log"
    logpath7 = rootpath + "analysis7.log"
    libpath = rootpath + "FIDO.pvl"
    resultpath = rootpath + "result/"
    @classmethod
    def initiate(cls):
        if os.path.exists(cls.logpath1):
            os.remove(cls.logpath1)
        if os.path.exists(cls.logpath2):
            os.remove(cls.logpath2)
        if os.path.exists(cls.logpath3):
            os.remove(cls.logpath3)
        if os.path.exists(cls.logpath4):
            os.remove(cls.logpath4)
        if os.path.exists(cls.logpath5):
            os.remove(cls.logpath5)
        if os.path.exists(cls.logpath6):
            os.remove(cls.logpath6)
        if os.path.exists(cls.logpath7):
            os.remove(cls.logpath7)
        if not os.path.exists(cls.libpath):
            print("FIDO.lib does not exist")
            sys.exit(1)
        if not os.path.exists(cls.regpath):
            print("reg.pv does not exist")
            sys.exit(1)
        if not os.path.exists(cls.authpath):
            print("auth.pv does not exist")
            sys.exit(1)

class Type:
    def __init__(self,name,write):
        self.name = name
        self.write = write

class Query:
    def __init__(self,name,write):
        self.name = name
        self.write = write

class Fields:
    def __init__(self, fields): # list
        self.nums = len(fields)
        self.write = ""
        self.name = "fields-" + str(self.nums)
        for item in fields:
            self.write += item
        self.fields = fields

class Entities:
    def __init__(self, entities):
        self.nums = len(entities)
        self.write = ""
        if self.nums == 0:
            self.name = "mali-" + str(self.nums) + "-none"
        else:
            self.name = "mali-" + str(self.nums) + "-" + entities[len(entities)-1][-7:-3]
        for item in entities:
            self.write += item
        self.entities = entities

class All_types:
    def __init__(self):
        self.all_types = []
    def size(self):
        return len(self.all_types)
    def get(self,i):
        return self.all_types[i]

class Reg_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b", "let atype = autr_1b in\n"))
        self.all_types.append(Type("autr_1r", "let atype = autr_1r in\n"))
        self.all_types.append(Type("autr_2b", "let atype = autr_2b in\n let ltype = stepup in"))
        self.all_types.append(Type("autr_2r", "let atype = autr_2r in\n let ltype = stepup in"))

class Auth_1b_em_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b_em","let atype = autr_1b in\n let ltype = empty in"))

class Auth_1b_st_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b_st","let atype = autr_1b in\n let ltype = stepup in"))

class Auth_1r_em_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1r_em","let atype = autr_1r in\n let ltype = empty in"))
class Auth_1r_st_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1r_st","let atype = autr_1r in\n let ltype = stepup in"))

class Auth_2b_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_2b", "let atype = autr_2b in\n let ltype = stepup in"))

class Auth_2r_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_2r", "let atype = autr_2r in\n let ltype = stepup in"))

class All_queries:
    def __init__(self):
        self.all_queries = []
        self.all_queries.append(Query("S-ak", "query secret testak.\n"))
        self.all_queries.append(Query("S-cntr","query secret testcntr.\n"))
        self.all_queries.append(Query("S-skau", "query secret testskAU.\n"))
        self.all_queries.append(Query("S-kid", "query secret testkid.\n"))
    def size(self):
        return len(self.all_queries)
    def get(self,i):
        return self.all_queries[i]

class Reg_queries(All_queries):
    def __init__(self):
        All_queries.__init__(self)
        self.all_queries.append(Query("S-skat", "query secret skAT.\n"))
        self.all_queries.append(Query("Rauth","query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_reg(u,a,aa,kid)) ==> (inj-event(Autr_verify_reg(u,a,aa,kid))==> inj-event(UA_init_reg(u,a))).\n"))

class Auth_stepup_queries(All_queries):
    def __init__(self):
        All_queries.__init__(self)
        self.all_queries.append(Query("S-tr","query secret tr.\n"))
        self.all_queries.append(Query("Aauth-tr", "query tr:Tr; inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr))).\n"))

class Auth_1b_em_queries(All_queries):
    def __init__(self):
        All_queries.__init__(self)
        self.all_queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u,a))).\n"))

class Auth_1b_st_queries(Auth_stepup_queries):
    def __init__(self):
        Auth_stepup_queries.__init__(self)
        self.all_queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u,a))).\n"))


class Auth_2b_queries(Auth_stepup_queries):
    def __init__(self):
        Auth_stepup_queries.__init__(self)
        self.all_queries.append(Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u,a))).\n"))

class Auth_1r_em_queries(All_queries):
    def __init__(self):
        All_queries.__init__(self)
        self.all_queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u,a))).\n"))

class Auth_1r_st_queries(Auth_stepup_queries):
    def __init__(self):
        Auth_stepup_queries.__init__(self)
        self.all_queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u,a))).\n"))

class Auth_2r_queries(Auth_stepup_queries):
    def __init__(self):
        Auth_stepup_queries.__init__(self)
        self.all_queries.append(Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u,a))).\n"))

class All_entities:
    def __init__(self):
        self.all_entities = []
    def get_all_scenes_reduce_version(self): #a scheme to get all combination of the entities
        self.entities = []
        for delnum in range(len(self.all_entities) + 1):
            for pre in itertools.combinations(self.all_entities, delnum):
                self.entities.append(Entities(pre))
    def get_all_scenes(self):
        self.entities = []
        for i in range(len(self.all_entities) + 1):
            temp_combination = []
            for j in range(i):
                temp_combination.append(self.all_entities[j])
            self.entities.append(Entities(temp_combination))


    def size(self):
        return len(self.entities)
    def get(self,i):
        return self.entities[i]

class Reg_entities(All_entities):
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("RegUC(c, MC, fakefacetid)| (*malicious-UA*)\n")
        self.all_entities.append("RegUA(https, c, uname,appid,password)| RegASM(c, AM, token, fakecallerid, atype)| (*malicious-UC*)\n")
        self.all_entities.append("RegUC(CU, c, facetid)| RegAutr(c, aaid, skAT, wrapkey, atype)| (*malicious-ASM*)\n")
        self.all_entities.append("RegASM(MC, c, token, callerid, atype)| (*-malicious-Autr*)\n")
        self.get_all_scenes()

class Auth_entities(All_entities):
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("AuthUC(c, MC, fakefacetid, ltype)| (*malicious-UA*)\n")
        self.all_entities.append("AuthUA(https, c, uname, ltype)| AuthASM(c,AM,token,fakecallerid,atype,ltype)| (*malicious-UC*)\n")
        self.all_entities.append("AuthUC(CU, c, facetid, ltype)| AuthAutr(c,aaid,wrapkey,cntr,tr,atype,ltype)| (*malicious-ASM*)\n")
        self.all_entities.append("AuthASM(MC,c,token,callerid,atype,ltype)| (*malicious-Autr*)\n")
        self.get_all_scenes()

class All_fields:
    def __init__(self):
        self.all_fields = []
        self.all_fields.append("out(c,token);\n")
        self.all_fields.append("out(c,wrapkey);\n")
    def get_all_scenes(self):
        self.fields = []
        for delnum in range(len(self.all_fields)+ 1) :
            for pre in itertools.combinations(self.all_fields, delnum):
                self.fields.append(Fields(pre))
    def size(self):
        return len(self.fields)
    def get(self,i):
        return self.fields[i]

class Reg_fields(All_fields):
    def __init__(self):
        All_fields.__init__(self)
        self.all_fields.append("out(c,skAT);\n")
        self.get_all_scenes()

class Auth_fields(All_fields):
    def __init__(self):
        All_fields.__init__(self)
        self.all_fields.append("out(c,skAU);\n")
        self.all_fields.append("out(c,cntr);\n")
        self.all_fields.append("out(c,kid);\n")
        self.get_all_scenes()

class Case:
    def __init__(self,p,t,q,f,e,lines,t_row,i_row):
        self.phase = p
        self.type = t
        self.query = q
        self.fields = f
        self.entities = e
        self.lines = lines # all lines in reg.pv or auth.pv
        self.type_set_row = t_row  # indicate type
        self.insert_row = i_row  # insert line number
        self.query_path = "TEMP-" + str(hash(Setting.rootpath + p + t.name + q.name + f.name + e.name)) + ".pv"
    def write_file(self,if_delete_parallel):
        f2 = open(self.query_path,"w")
        if(if_delete_parallel):
            for i in range(len(self.lines)):
                self.lines[i] = self.lines[i].replace('!','')
        f2.writelines(self.query.write)
        for i in range(len(self.lines)):
            if i == self.type_set_row:
                f2.writelines(self.type.write)
            if i == self.insert_row:
                f2.writelines(self.fields.write)
                f2.writelines(self.entities.write)
            f2.writelines(self.lines[i])
        f2.close()

    def analyze(self):
        self.write_file(True)
        ret, result = self.proverif()
        if ret == 'false':
            self.state = ret
            f = open(self.query_path)
            content = f.readlines()
            f.close()
            os.remove(self.query_path)
            return ret, result, content
        else:
            self.write_file(False)
            ret, result = self.proverif()
            self.state = ret
            f = open(self.query_path)
            content = f.readlines()
            f.close()
            os.remove(self.query_path)
            return ret, result, content

    def proverif(self):
        output = Popen('proverif -lib "' + Setting.libpath + '" ' + self.query_path, stdout=PIPE, stderr=PIPE)
        timer = Timer(20, lambda process: process.kill(), [output])
        try:
            timer.start()
            stdout, stderr = output.communicate()
            return_code = output.returncode
        finally:
            timer.cancel()
        i = stdout[0:-10].rfind(b'--------------------------------------------------------------')
        result = stdout[i:-1]
        #print(result)
        if result == b"" or len(result) == 0:
            result = stdout[-1000:-1]
            ret = 'tout'
        elif (result.find(b'error') != -1):
            ret = 'error'
        elif (result.find(b'false') != -1):
            ret = 'false'
        elif (result.find(b'hypothesis:') != -1):
            ret = 'trace'
        elif (result.find(b'prove') != -1):
            ret = 'prove'
        elif (result.find(b'true') != -1):
            ret = 'true'
        else:
            ret = 'tout'
        self.state = ret
        self.result = result
        return ret, result

    def danger_than(self,case2): # whether this case is dangerthan case2
        if self.type != case2.type:
            return False
        if self.query != case2.query:
            return False
        if not operator.eq(self.fields.fields,case2.fields.fields):
            return False
        if case2.entities.nums > self.entities.nums:
            return False
        return True



class Generator: #generator cases
    def __init__(self,phase):
        if phase == "reg":
            self.phase = "reg"
            self.lines = self.read_file(phase)
            self.types = Reg_types()
            self.fields = Reg_fields()
            self.entities = Reg_entities()
            self.queries = Reg_queries()
            self.type_set_row = Setting.reg_set_type_row  # indicate type
            self.insert_row = Setting.reg_insert_row  # insert line number
        else:           
            self.fields = Auth_fields()
            self.entities = Auth_entities()
            self.type_set_row = Setting.auth_set_type_row  # indicate type
            self.insert_row = Setting.auth_insert_row  # insert line number
            if phase == "auth_1b_em":
                self.types = Auth_1b_em_types()
                self.phase = phase
                self.queries = Auth_1b_em_queries()
                self.lines = self.read_file(phase)
            elif phase == "auth_1b_st":
                self.types = Auth_1b_st_types()
                self.phase = phase
                self.queries = Auth_1b_st_queries()
                self.lines = self.read_file(phase)
            elif phase == "auth_1r_em":
                self.types = Auth_1r_em_types()
                self.phase = phase
                self.queries = Auth_1r_em_queries()
                self.lines = self.read_file(phase)
            elif phase == "auth_1r_st":
                self.types = Auth_1r_st_types()
                self.phase = phase
                self.queries = Auth_1r_st_queries()
                self.lines = self.read_file(phase)
            elif phase == "auth_2b":
                self.types = Auth_2b_types()
                self.phase = phase
                self.queries = Auth_2b_queries()
                self.lines = self.read_file(phase)
            elif phase == "auth_2r":
                self.types = Auth_2r_types()
                self.phase = phase
                self.queries = Auth_2r_queries()
                self.lines = self.read_file(phase)
        self.reverse_f_e() #reverse all
        self.t_nums = self.types.size()
        self.q_nums = self.queries.size()
        self.f_nums = self.fields.size()
        self.e_nums = self.entities.size()
        self.t_cur = 0
        self.q_cur = 0
        self.f_cur = 0
        self.e_cur = -1
    def read_file(self,phase):
        if phase == "reg":
            f = open(Setting.regpath)
            lns = f.readlines()
        elif phase == "auth_1r_em" or phase == "auth_1b_em":
            f = open(Setting.authpath)
            lns = []
            tttt = f.readlines()
            for i in range(len(tttt)):
                if i == self.insert_row:
                    lns.append("AuthRP(c,uname, appid, aaid,kid,pkAU,cntr,tr,ltype)| (*add RP to c for first login*)")
                else:
                    lns.append(tttt[i])
        else:
            f = open(Setting.authpath)
            lns = f.readlines()
        f.close()
        return lns


    def generater_case(self):
        if self.increase() == False:
            return False, 0
        else:
            p = self.phase
            t = self.types.get(self.t_cur)
            q = self.queries.get(self.q_cur)
            f = self.fields.get(self.f_cur)
            e = self.entities.get(self.e_cur)
            case = Case(p,t,q,f,e,self.lines,self.type_set_row,self.insert_row)
            return True, case

    def increase(self):
        if self.e_cur >= self.e_nums - 1:
            self.e_cur = 0
            if(self.f_cur >= self.f_nums - 1):
                self.f_cur = 0
                if(self.q_cur >= self.q_nums - 1):
                    self.q_cur = 0
                    if(self.t_cur >= self.t_nums - 1):
                        return False
                    else:
                        self.t_cur = self.t_cur + 1
                else:
                    self.q_cur = self.q_cur + 1
            else:
                self.f_cur = self.f_cur + 1
        else:
            self.e_cur = self.e_cur + 1
        return True
    def set_last_state(self,state): #set last state
        if state == 'true':
            self.e_cur = self.e_nums

    def reverse_f_e(self):
        self.fields.fields.reverse()
        self.entities.entities.reverse()

class Assist:
    def __init__(self):
        self.is_set = False
    def append(self,case):
        self.false_case = case
        self.is_set = True
    def jump(self,case):
        if case.state != 'false':
            return False
        if not self.is_set:
            self.append(case)
            return False
        else:
            if case.danger_than(self.false_case):
                return True
            else:
                self.append(case)
                return False

            



def analysis(phase,log):
    gen = Generator(phase)
    assist = Assist()
    count = 0
    while True:
        r, case = gen.generater_case()
        msg = str(count).ljust(5)
        msg += phase.ljust(4)
        if r == False:
            break
        ret, result, content = case.analyze()
        if ret == 'false':
            msg += " false"
        elif ret == 'true':
            msg += "  true"
        elif ret == 'prove':
            msg += " prove"
        elif ret == 'tout':
            msg += "  tout"
        else:
            msg += " error"
        gen.set_last_state(ret)
        msg += " type "
        msg += case.type.name.ljust(4)
        msg += " query "
        msg += case.query.name.ljust(4)
        msg += str(case.fields.name).ljust(9)
        msg += " "
        msg += str(case.entities.name).ljust(8)
        write_log(msg,log)
        count = count + 1
        if ret == 'false':
            continue
        if not os.path.exists(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name):
            os.makedirs(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name)
        f = open(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name + "/" + msg, "w")
        f.writelines(content)
        f.writelines(str(result[-1000:-1]))
        f.close()

def write_log(msg,log):
    print(msg, file = log)

if __name__ == "__main__":
    Setting.initiate()
    log1 = open(Setting.logpath1, mode='a+', encoding='utf-8')
    log2 = open(Setting.logpath2, mode='a+', encoding='utf-8')
    log3 = open(Setting.logpath3, mode='a+', encoding='utf-8')
    log4 = open(Setting.logpath4, mode='a+', encoding='utf-8')
    log5 = open(Setting.logpath5, mode='a+', encoding='utf-8')
    log6 = open(Setting.logpath6, mode='a+', encoding='utf-8')
    log7 = open(Setting.logpath7, mode='a+', encoding='utf-8')
    t1 = threading.Thread(target=analysis, args=("reg", log1))
    t2 = threading.Thread(target=analysis, args=("auth_1b_em", log2))
    t3 = threading.Thread(target=analysis, args=("auth_1b_st", log3))
    t4 = threading.Thread(target=analysis, args=("auth_1r_em", log4))
    t5 = threading.Thread(target=analysis, args=("auth_1r_st", log5))
    t6 = threading.Thread(target=analysis, args=("auth_2b", log6))
    t7 = threading.Thread(target=analysis, args=("auth_2r", log7))
    tlist = [t1,t2,t3,t4,t5,t6,t7]
    #tlist = [t1]
    for t in tlist:
        t.start()
    for t in tlist:
        t.join()
    log1.close()
    log2.close()
    log3.close()
    log4.close()
    log5.close()
