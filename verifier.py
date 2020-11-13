import itertools
import os
import sys
import threading
import getopt
from threading import Timer
from subprocess import Popen, PIPE


class Setting:
    '''
    General setting class
    pleas set the rootpath when you first start
    rootpath is the directory of the directory where the .pv and .pvl files put
    You can set it directly to the parent directory of the current directory
    '''
    rootpath = os.getcwd() + "/"
    reg_set_type_row = 4
    reg_insert_row = 21
    auth_set_type_row = 7
    auth_insert_row = 31
    regpath = rootpath + "reg.pv"
    authpath = rootpath + "auth.pv"
    logpath1 = rootpath + "reg.log"
    logpath2 = rootpath + "LOG" + "auth_1b_em.log"
    logpath3 = rootpath + "LOG" + "auth_1b_st.log"
    logpath4 = rootpath + "LOG" + "auth_1r_em.log"
    logpath5 = rootpath + "LOG" + "auth_1r_st.log"
    logpath6 = rootpath + "LOG" + "auth_2b.log"
    logpath7 = rootpath + "LOG" + "auth_2r.log"
    libpath = rootpath + "FIDO.pvl"
    resultpath = rootpath + "result/"
    @classmethod
    def initiate(cls):
        if not os.path.exists(cls.libpath):
            print("FIDO.pvl does not exist")
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
    def __init__(self, entities, row_numbers):
        self.nums = len(entities)
        self.write = ""
        if self.nums == 0:
            self.name = "mali-" + str(self.nums)
        else:
            self.name = "mali-" + str(self.nums) + " "
            for i in row_numbers:
                self.name += "," + str(i)
        for item in entities:
            self.write += item
        self.entities = entities
        self.row_numbers = row_numbers


class All_types:
    '''
    a parant class for all authenticator types
    use the specific subclass when analyzing
    '''
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
        self.all_types.append(Type("autr_2b", "let atype = autr_2b in\nlet ltype = stepup in \n"))
        self.all_types.append(Type("autr_2r", "let atype = autr_2r in\nlet ltype = stepup in \n"))

class Auth_1b_em_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b_em","let atype = autr_1b in\nlet ltype = empty in \n"))

class Auth_1b_st_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b_st","let atype = autr_1b in\nlet ltype = stepup in \n"))

class Auth_1r_em_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1r_em","let atype = autr_1r in\nlet ltype = empty in \n"))
class Auth_1r_st_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1r_st","let atype = autr_1r in\nlet ltype = stepup in \n"))

class Auth_2b_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_2b", "let atype = autr_2b in\nlet ltype = stepup in \n"))

class Auth_2r_types(All_types):
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_2r", "let atype = autr_2r in\nlet ltype = stepup in \n"))

class All_queries:
    '''
    a parant class for all queries
    this class indicate the queries for all types of authenticator and all phases(reg/auth)
    use the specific subclass when analyzing
    you can add queries as you wish
    '''
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
        self.all_queries.append(Query("S-tr","query secret testtr.\n"))
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
    '''
   a parant class for all possible combinations of malicous entities
   you can just write all the possible malicous in subclass for each phase(reg/auth)
   this parant class will generate all the combinations.
   version2 is a reduce plan
   '''
    def __init__(self):
        self.all_entities = []
    def get_all_scenes(self): #a scheme to get all combination of the entities
        self.entities = []
        for delnum in range(len(self.all_entities) + 1):
            for row_numbers in itertools.combinations(range(len(self.all_entities)), delnum):
                temp = []
                for i in row_numbers:
                    temp.append(self.all_entities[i])
                self.entities.append(Entities(temp,row_numbers))

    def get_all_scenes_version2(self):
        self.entities = []
        for i in range(len(self.all_entities) + 1):
            temp_combination = []
            row_numbers = []
            for j in range(i):
                temp_combination.append(self.all_entities[j])
            self.entities.append(Entities(temp_combination))
    def size(self):
        return len(self.entities)
    def get(self,i):
        return self.entities[i]

class Reg_entities_version2(All_entities):
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("RegUC(c, MC, fakefacetid)| (*malicious-UA*)\n")
        self.all_entities.append("RegUA(https, c, uname,appid,password)| RegASM(c, AM, token, fakecallerid, atype)| (*malicious-UC*)\n")
        self.all_entities.append("RegUC(CU, c, facetid)| RegAutr(c, aaid, skAT, wrapkey, atype)| (*malicious-ASM*)\n")
        self.all_entities.append("RegASM(MC, c, token, callerid, atype)| (*-malicious-Autr*)\n")
        self.get_all_scenes()

class Reg_entities(All_entities):
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("RegUA(https, c, uname,appid,password)|\n")
        self.all_entities.append("RegUC(c, MC, fakefacetid)|\n")
        self.all_entities.append("RegUC(CU, c, facetid)|\n")
        self.all_entities.append("RegUC(c, c, fakefacetid)|\n")
        self.all_entities.append("RegASM(c, AM, token, fakecallerid, atype)|\n")
        self.all_entities.append("RegASM(MC, c, token, callerid, atype)|\n")
        self.all_entities.append("RegASM(c, c, token, fakecallerid, atype)|\n")
        self.all_entities.append("RegAutr(c, aaid, skAT, wrapkey, atype)|\n")
        self.get_all_scenes()

class Auth_entities(All_entities):
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("AuthUA(https, c, uname, ltype)|\n")
        self.all_entities.append("AuthUC(c, MC, fakefacetid, ltype)|\n")
        self.all_entities.append("AuthUC(CU, c, facetid, ltype)|\n")
        self.all_entities.append("AuthUC(c, c, fakefacetid, ltype)|\n")
        self.all_entities.append("AuthASM(c,AM,token,fakecallerid,atype,ltype)|\n")
        self.all_entities.append("AuthASM(MC,c,token,callerid,atype,ltype)|\n")
        self.all_entities.append("AuthASM(c,c,token,fakecallerid,atype,ltype)|\n")
        self.all_entities.append("AuthAutr(c,aaid,wrapkey,cntr,tr,atype,ltype)| \n")
        self.get_all_scenes()

class Auth_entities_version2(All_entities):
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("AuthUC(c, MC, fakefacetid, ltype)| (*malicious-UA*)\n")
        self.all_entities.append("AuthUA(https, c, uname, ltype)| AuthASM(c,AM,token,fakecallerid,atype,ltype)| (*malicious-UC*)\n")
        self.all_entities.append("AuthUC(CU, c, facetid, ltype)| AuthAutr(c,aaid,wrapkey,cntr,tr,atype,ltype)| (*malicious-ASM*)\n")
        self.all_entities.append("AuthASM(MC,c,token,callerid,atype,ltype)| (*malicious-Autr*)\n")
        self.get_all_scenes()

class All_fields:
    '''
    A parant class for all possible combinations of the compromised fields
    this file does not consider the compromise of the fields since it lead to too much time to run
    if you want to analyze the case when there are fields being compormised use "get_all_scenes_version2"
    '''
    def __init__(self):
        self.all_fields = []
        self.all_fields.append("out(c,token);\n")
        self.all_fields.append("out(c,wrapkey);\n")
    def get_all_scenes(self): #a version that no fields will be compromised.
        self.fields = [Fields(["(* no fields being compromised *)\n"])]
    def get_all_scenes_version2(self):
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
    '''
    A specific case which
    phase : registration or authentication
    type : the type of the authenticator
    query : a query
    fields : the fields has been compromised
    entities: the malicous entities scenes
    '''
    def __init__(self,p,t,q,f,e,lines,t_row,i_row):
        self.phase = p
        self.type = t
        self.query = q
        self.fields = f
        self.entities = e
        self.lines = lines # all lines in reg.pv or auth.pv
        self.type_set_row = t_row  # indicate type
        self.insert_row = i_row  # insert line number
        self.query_path = "TEMP/" + "TEMP-" + str(hash(Setting.rootpath + p + t.name + q.name + f.name + e.name)) + ".pv"

    def write_file(self,if_delete_parallel):
        '''
        write the query file for proverif to verify
        '''
        f2 = open(self.query_path,"w")
        analyze_lines = []
        if(if_delete_parallel):# if true, then remove ! to speed up analyzing
            for i in range(len(self.lines)):
                analyze_lines.append(self.lines[i].replace('!',''))
        else:
            analyze_lines = self.lines
        f2.writelines(self.query.write)
        for i in range(len(analyze_lines)):
            if i == self.type_set_row:
                f2.writelines(self.type.write)
            if i == self.insert_row:
                f2.writelines(self.fields.write)
                f2.writelines(self.entities.write)
            f2.writelines(analyze_lines[i])
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
            if result.find(b'a trace has been found.'):
                ret = 'false'
            elif result.find(b'trace'):
                ret = 'mayfalse'
            else:
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



class Generator: #generator cases
    '''
    giving the all phase, types, fields, entities, queries, this class generate a specific case.
    besides, this class maintain a secure sets to speed up the case which is subset
    '''
    def __init__(self,phase):
        self.secure_sets = []
        self.noprove_sets = []
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
                    lns.append("AuthRP(c,uname, appid, aaid,kid,pkAU,cntr,tr,ltype)| (*add RP to c for first login*)\n")
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
            self.secure_sets.clear()
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
    def reverse_f_e(self):
        self.fields.fields.reverse()
        self.entities.entities.reverse()
    def this_case_is_secure(self):#add a secure sets
        self.secure_sets.append(self.entities.get(self.e_cur).row_numbers)
    def jump_if_its_secure(self):
        for secur_case in self.secure_sets:
            cur_case = self.entities.get(self.e_cur).row_numbers
            if(set(cur_case).issubset(set(secur_case))):
                return True
        return False
    def this_case_is_noprove(self):
        self.noprove_sets.append(self.entities.get(self.e_cur).row_numbers)
    def jump_if_its_noprove(self):
        for noprove_case in self.noprove_sets:
            cur_case = self.entities.get(self.e_cur).row_numbers
            if(set(cur_case).issubset(set(noprove_case))):
                return True
        return False

def analysis(phase,log):
    '''
    giving the phase and a log file name, then analyzing
    '''
    gen = Generator(phase)
    count = 0
    while True:
        r, case = gen.generater_case()
        if r == False:
            break
        if(gen.jump_if_its_secure()):
            msg = str(count).ljust(5) + phase.ljust(4) + "skipping for secure sets"
        elif(gen.jump_if_its_noprove()):
            msg = str(count).ljust(5) + phase.ljust(4) + "skipping for noprove sets"
        else:
            msg = str(count).ljust(5) + phase.ljust(4)
            ret, result, content = case.analyze()
            if ret == 'true':
                gen.this_case_is_secure()
                msg += "  true"
            else:
                msg += "  " + ret
            #gen.set_last_state(ret)
            msg += " type "
            msg += case.type.name.ljust(4)
            msg += " query "
            msg += case.query.name.ljust(4)
            msg += str(case.fields.name).ljust(9)
            msg += " "
            msg += str(case.entities.name).ljust(8)
            if ret != 'false': #if false then do not write the analysis file
                if not os.path.exists(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name):
                    os.makedirs(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name)
                f = open(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name + "/" + msg, "w")
                f.writelines(content)
                f.writelines(str(result[-1000:-1]))
                f.close()
        count = count + 1
        write_log(msg, log)
        log.flush()

def write_log(msg,log):
    print(msg, file = log)

			
	
if __name__ == "__main__":
    Setting.initiate()
    log1 = open(Setting.logpath1, mode='w+', encoding='utf-8')
    log2 = open(Setting.logpath2, mode='w+', encoding='utf-8')
    log3 = open(Setting.logpath3, mode='w+', encoding='utf-8')
    log4 = open(Setting.logpath4, mode='w+', encoding='utf-8')
    log5 = open(Setting.logpath5, mode='w+', encoding='utf-8')
    log6 = open(Setting.logpath6, mode='w+', encoding='utf-8')
    log7 = open(Setting.logpath7, mode='w+', encoding='utf-8')
    t1 = threading.Thread(target=analysis, args=("reg", log1))
    t2 = threading.Thread(target=analysis, args=("auth_1b_em", log2))
    t3 = threading.Thread(target=analysis, args=("auth_1b_st", log3))
    t4 = threading.Thread(target=analysis, args=("auth_1r_em", log4))
    t5 = threading.Thread(target=analysis, args=("auth_1r_st", log5))
    t6 = threading.Thread(target=analysis, args=("auth_2b", log6))
    t7 = threading.Thread(target=analysis, args=("auth_2r", log7))
    tlist = [t1,t2,t3,t4,t5,t6,t7]#run all th phase
    
    try:
        options, args = getopt.getopt(sys.argv[1:], "ht:", ["help", "target="])
    except getopt.GetoptError:
        sys.exit()
    for option, value in options:
        if option in ("-h", "-help", "--help"):
            print("usage: [-help] [-t]")
            sys.exit()
        if option in ("-t","--t","--target","-target"):
            tlist = []
            if str(value) == "reg":
                tlist.append(t1)
            if str(value) == "auth_1b_em":
                tlist.append(t2)
            if str(value) == "auth_1b_st":
                tlist.append(t3)
            if str(value) == "auth_1r_em":
                tlist.append(t4)
            if str(value) == "auth_1r_st":
                tlist.append(t5)
            if str(value) == "auth_2b":
                tlist.append(t6)
            if str(value) == "auth_2r":
                tlist.append(t7)
            
    print(tlist)
    for t in tlist:
        t.start()
    for t in tlist:
        t.join()
    log1.close()
    log2.close()
    log3.close()
    log4.close()
    log5.close()
