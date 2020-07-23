import itertools
import os
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
    querypath = rootpath + "query.pv"
    temppath = rootpath + "temp.pv"
    regpath = rootpath + "reg.pv"
    authpath = rootpath + "auth.pv"
    logpath = rootpath + "analysis.log"
    libpath = rootpath + "FIDO.pvl"
    resultpath = rootpath + "result/"

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
        self.name = "out data fields"
        self.nums = len(fields)
        self.write = ""
        for item in fields:
            self.write += item
        self.fields = fields

class Entities:
    def __init__(self, entities):
        self.name = "malicious entities"
        self.nums = len(entities)
        self.write = ""
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
        self.path = path
        self.type_set_row = t_row  # indicate type
        self.insert_row = i_row  # insert line number
    def write_file(self,if_delete_parallel):
        f1 = open(self.path,"r")
        f2 = open(Setting.querypath,"w")
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
            return ret, result
        else:
            self.write_file(False)
            return self.proverif()

    def proverif(self):
        output = Popen('proverif -lib "' + Setting.libpath + '" ' + Setting.querypath, stdout=PIPE, stderr=PIPE)
        timer = Timer(20, lambda process: process.kill(), [output])
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

class All_types:
    def __init__(self):
        self.all_types = []
        self.all_types.append(Type("autr_2b", "let atype = autr_2b in\n let ltype = stepup in"))
        self.all_types.append(Type("autr_2r", "let atype = autr_2r in\n let ltype = stepup in"))
    def size(self):
        return len(self.all_types)
    def get(self,i):
        return self.all_types[i]

class Reg_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b", "let atype = autr_1b in\n"))
        self.all_types.append(Type("autr_1r", "let atype = autr_1r in\n"))

class Auth_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b_em","let atype = autr_1b in\n let ltype = empty in"))
        self.all_types.append(Type("autr_1b_st","let atype = autr_1b in\n let ltype = stepup in"))
        self.all_types.append(Type("autr_1r_em","let atype = autr_1r in\n let ltype = empty in"))
        self.all_types.append(Type("autr_1r_st","let atype = autr_1r in\n let ltype = stepup in"))

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
    def get_all_scenes(self):
        self.entities = []
        temp_combination = []
        for i in range(len(self.all_entities)):
            tmp_str = ""
            for j in range(i + 1):
                temp_combination.append(self.all_entities[j])
            self.entities.append(Entities(temp_combination))
    def size(self):
        return len(self.all_entities)
    def get(self,i):
        return self.entities[i]

class Reg_entities(All_entities):
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("RegUC(c, MC, fakefacetid)|\n")
        self.all_entities.append("RegUA(https, c, uname,appid,password)|\n")
        self.all_entities.append("RegASM(c, AM, token, fakecallerid, atype)|\n")
        self.all_entities.append("RegUC(CU, c, facetid)|\n")
        self.all_entities.append("RegAutr(c, aaid, skAT, wrapkey, atype)|\n")
        self.all_entities.append("RegASM(MC, c, token, callerid, atype)|\n")
        self.get_all_scenes()

class Auth_entities(All_entities):
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("AuthUC(c, MC, fakefacetid, ltype)|\n")
        self.all_entities.append("AuthUA(https, c, uname, ltype)|\n")
        self.all_entities.append("AuthASM(c,AM,token,fakecallerid,atype,ltype)|\n")
        self.all_entities.append("AuthUC(CU, c, facetid, ltype)|\n")
        self.all_entities.append("AuthAutr(c,aaid,wrapkey,cntr,atype,ltype)|\n")
        self.all_entities.append("AuthASM(MC,c,token,callerid,atype,ltype)|\n")
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
        return len(self.all_fields)
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
            self.types = Auth_types()
            self.fields = Auth_fields()
            self.entities = Auth_entities()
            self.path = Setting.authpath
            self.type_set_row = 4  # indicate type
            self.insert_row = 31  # insert line number
            if phase == "auth_1br":
                self.phase = "auth_1br"
                self.queries = Auth_1br_queries()
            elif phase == "auth_2br":
                self.phase = "auth_1br"
                self.queries = Auth_1br_queries()
        self.t_nums = self.types.size()
        self.q_nums = self.queries.size()
        self.f_nums = self.fields.size()
        self.e_nums = self.entities.size()
        self.t_cur = 0
        self.q_cur = 0
        self.f_cur = -1
        self.e_cur = 0
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
        if self.f_cur == self.f_nums - 1:
            self.f_cur = 0
            if(self.e_cur == self.e_nums - 1):
                self.e_cur = 0
                if(self.q_cur == self.q_nums - 1):
                    self.q_cur = 0
                    if(self.t_cur == self.t_nums - 1):
                        return False
                    else:
                        self.t_cur = self.t_cur + 1
                else:
                    self.q_cur = self.q_cur + 1
            else:
                self.e_cur = self.e_cur + 1
        else:
            self.f_cur = self.f_cur + 1
        return True

def analysis(phase):
    gen = Generator(phase)
    count = 0
    log = open(Setting.logpath, mode='a', encoding='utf-8')
    while True:
        r, case = gen.generater_case()
        if r == False:
            break
        msg = str(count).ljust(4)
        ret, result = case.analyze()
        if ret == 'false':
            msg += " false"
        elif ret == 'true':
            msg += "  true"
        elif ret == 'prove':
            msg += " prove"
        else:
            msg += "  error"
        msg += " type-"
        msg += case.type.name.ljust(8)
        msg += " query-"
        msg += case.query.name.ljust(8)
        msg += " malie-"
        msg += str(case.entities.nums).ljust(2)
        msg += " compf-"
        msg += str(case.fields.nums).ljust(2)
        print(msg)
        count = count + 1
        if ret == "true":
            continue
        if not os.path.exists(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name):
            os.makedirs(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name)
        f = open(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name + "/" + msg, "w")
        f2 = open(Setting.querypath, "r")
        f.writelines(f2.readlines())
        f.writelines(str(result[-1000:-1]))
        f.close()
        f2.close()
    log.close()


analysis("reg")
analysis("auth_1br")
analysis("auth_2br")