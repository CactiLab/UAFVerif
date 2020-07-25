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
    rootpath = "D:/Work/proverif2.01/FIDO/"
    #rootpath = "D:/me/proverif2.01/FIDO/"
    #querypath = rootpath + "query.pv"
    temppath = rootpath + "temp.pv"
    regpath = rootpath + "reg.pv"
    authpath = rootpath + "auth.pv"
    logpath1 = rootpath + "analysis1.log"
    logpath2 = rootpath + "analysis2.log"
    logpath3 = rootpath + "analysis3.log"
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

class Case:
    def __init__(self,p,t,q,f,e,path,t_row,i_row):
        self.phase = p
        self.type = t
        self.query = q
        self.fields = f
        self.entities = e
        self.path = path # indicate reg.pv or auth.pv
        self.type_set_row = t_row  # indicate type
        self.insert_row = i_row  # insert line number
        self.query_path = Setting.rootpath + p + t.name + q.name + f.name + e.name + ".pv"
    def write_file(self,if_delete_parallel):
        f1 = open(self.path,"r")
        f2 = open(self.query_path,"w")
        lines = f1.readlines()
        if(if_delete_parallel):
            for i in range(len(lines)):
                lines[i] = lines[i].replace('!','')
        f2.writelines(self.query.write)
        for i in range(len(lines)):
            if i == self.type_set_row:
                f2.writelines(self.type.write)
            if i == self.insert_row:
                f2.writelines(self.fields.write)
                f2.writelines(self.entities.write)
            f2.writelines(lines[i])
        f1.close()
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
        if (result.find(b'error') != -1):
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

class Auth_1br_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b_em","let atype = autr_1b in\n let ltype = empty in"))
        self.all_types.append(Type("autr_1b_st","let atype = autr_1b in\n let ltype = stepup in"))
        self.all_types.append(Type("autr_1r_em","let atype = autr_1r in\n let ltype = empty in"))
        self.all_types.append(Type("autr_1r_st","let atype = autr_1r in\n let ltype = stepup in"))

class Auth_2br_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_2b", "let atype = autr_2b in\n let ltype = stepup in"))
        self.all_types.append(Type("autr_2r", "let atype = autr_2r in\n let ltype = stepup in"))

class All_queries:
    def __init__(self):
        self.all_queries = []
        self.all_queries.append(Query("S-ak", "query secret testak.\n"))
        self.all_queries.append(Query("S-cntr","query secret cntr.\n"))
        self.all_queries.append(Query("S-skau", "query secret skAU.\n"))
    def size(self):
        return len(self.all_queries)
    def get(self,i):
        return self.all_queries[i]

class Reg_queries(All_queries):
    def __init__(self):
        All_queries.__init__(self)
        self.all_queries.append(Query("S-skat", "query secret skAT.\n"))
        self.all_queries.append(Query("Rauth","query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_reg(u,a,aa,kid)) ==> (inj-event(Autr_verify_reg(u,a,aa,kid))==> inj-event(UA_init_reg(u,a))).\n"))

class Auth_queries(All_queries):
    def __init__(self):
        All_queries.__init__(self)
        self.all_queries.append(Query("S-tr","query secret tr.\n"))
        self.all_queries.append(Query("auth-tr", "query tr:Tr; inj-event(RP_success_tr(tr)) ==> inj-event(Autr_verify_tr(tr)).\n"))

class Auth_1br_queries(Auth_queries):
    def __init__(self):
        Auth_queries.__init__(self)
        self.all_queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> inj-event(Autr_verify_auth_1br(u,a,aa,kid)).\n"))

class Auth_2br_queries(Auth_queries):
    def __init__(self):
        Auth_queries.__init__(self)
        self.all_queries.append(Query("Aauth-2br","query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> inj-event(Autr_verify_auth_2br(a,aa,kid)).\n"))

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
        self.all_entities.append("AuthUC(CU, c, facetid, ltype)| AuthAutr(c,aaid,wrapkey,cntr,atype,ltype)| (*malicious-ASM*)\n")
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
        self.get_all_scenes()

class Generator: #generator cases
    def __init__(self,phase):
        if phase == "reg":
            self.phase = "reg"
            self.path = Setting.regpath
            self.types = Reg_types()
            self.fields = Reg_fields()
            self.entities = Reg_entities()
            self.queries = Reg_queries()
            self.type_set_row = 3  # indicate type
            self.insert_row = 24  # insert line number
        else:           
            self.fields = Auth_fields()
            self.entities = Auth_entities()
            self.path = Setting.authpath
            self.type_set_row = 4  # indicate type
            self.insert_row = 31  # insert line number
            if phase == "auth_1br":
                self.types = Auth_1br_types()
                self.phase = "auth_1br"
                self.queries = Auth_1br_queries()
            elif phase == "auth_2br":
                self.types = Auth_2br_types()
                self.phase = "auth_2br"
                self.queries = Auth_2br_queries()
        self.reverse_f_e() #reverse all
        self.t_nums = self.types.size()
        self.q_nums = self.queries.size()
        self.f_nums = self.fields.size()
        self.e_nums = self.entities.size()
        self.t_cur = 0
        self.q_cur = 0
        self.f_cur = 0
        self.e_cur = -1
    def generater_case(self):
        if self.increase() == False:
            return False, 0
        else:
            p = self.phase
            t = self.types.get(self.t_cur)
            q = self.queries.get(self.q_cur)
            f = self.fields.get(self.f_cur)
            e = self.entities.get(self.e_cur)
            case = Case(p,t,q,f,e,self.path,self.type_set_row,self.insert_row)
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
        else:
            msg += " error"
        gen.set_last_state(ret)
        msg += " type "
        msg += case.type.name.ljust(4)
        msg += " query "
        msg += case.query.name.ljust(4)
        msg += str(case.fields.name).ljust(9)
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
    print(msg,file = log)

def analyze_reg_thread(log):
    analysis("reg",log)
def analyze_auth1br_thread(log):
    analysis("auth_1br",log)
def analyze_auth2br_thread(log):
    analysis("auth_2br",log)

if __name__ == "__main__":
    Setting.initiate()
    log1 = open(Setting.logpath1, mode='a+', encoding='utf-8')
    log2 = open(Setting.logpath2, mode='a+', encoding='utf-8')
    log3 = open(Setting.logpath3, mode='a+', encoding='utf-8')
    t1 = threading.Thread(target=analyze_reg_thread, args=(log1,))
    t2 = threading.Thread(target=analyze_auth1br_thread, args=(log2,))
    t3 = threading.Thread(target=analyze_auth2br_thread, args=(log3,))
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()
    log1.close()
    log2.close()
    log3.close()
