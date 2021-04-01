import itertools
import os
import sys
import threading
import getopt
import time
from threading import Timer
from subprocess import Popen, PIPE


class Setting:
    '''
    General setting class
    rootpath is the directory where the .pv and .pvl files put
    '''
    rootpath = os.getcwd() + "/"
    reg_set_type_row = 4 #indicate which row to insert "let atype = xxx"
    reg_insert_row = 23   #indicate which row to insert malicious entities
    auth_set_type_row = 8
    auth_insert_row = 35
    regpath = rootpath + "reg.pv"
    authpath = rootpath + "auth.pv"
    if not os.path.exists(rootpath + "LOG/"):
        os.makedirs(rootpath + "LOG/")
    logpath1 = rootpath + "LOG/" + "reg.log"
    logpath2 = rootpath + "LOG/" + "auth_1b_em.log"
    logpath3 = rootpath + "LOG/" + "auth_1b_st.log"
    logpath4 = rootpath + "LOG/" + "auth_1r_em.log"
    logpath5 = rootpath + "LOG/" + "auth_1r_st.log"
    logpath6 = rootpath + "LOG/" + "auth_2b.log"
    logpath7 = rootpath + "LOG/" + "auth_2r.log"
    libpath = rootpath + "UAF.pvl"
    resultpath = rootpath + "result/"
    analyze_flag = "full" #full to analze all scenarios, simple to analyze without fields leakage.
    @classmethod
    def initiate(cls): # judge if the setting is ready for running
        if not os.path.exists(cls.libpath):
            print("FIDO.pvl does not exist")
            sys.exit(1)
        if not os.path.exists(cls.regpath):
            print("reg.pv does not exist")
            sys.exit(1)
        if not os.path.exists(cls.authpath):
            print("auth.pv does not exist")
            sys.exit(1)

class Type: #indicate the type of the authenticator
    def __init__(self,name,write):
        self.name = name #for example "autr_1b“
        self.write = write # indicate how to write the type in .pv file, for example "let atype = autr_1b"

class Query: # indicate a specific query
    def __init__(self,name,write):
        self.name = name #for example, the confidentiality of ak: S-ak
        self.write = write # indicate how to write the query in .pv file

class Fields: # indicate a specific combination of compromised fields
    def __init__(self, fields, row_numbers): # initiate by a list
        self.nums = len(fields)  # number of the malicious fields
        self.write = "" # how to write those fields in .pv file
        self.name = "fields-" + str(self.nums) # give it a name to generate the output files
        for item in fields:
            self.write += item
        self.fields = fields
        self.row_numbers = row_numbers

class Entities: # indicate a specific combination of malicious entities
    def __init__(self, entities, row_numbers): # initiate by a list and which rows in the list to add
        self.nums = len(entities) # how many entities
        self.write = "" # how to write the malicious entities in .pv file
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
    a parant class for all possible authenticator types
    use the specific subclass when analyzing
    '''
    def __init__(self):
        self.all_types = []
    def size(self):
        return len(self.all_types)
    def get(self,i):
        return self.all_types[i]

class Reg_types(All_types): # Reg types
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b_null", "let atype = autr_1b in\nlet ftype = null in \n"))
        self.all_types.append(Type("autr_1r_null", "let atype = autr_1r in\nlet ftype = null in \n"))
        self.all_types.append(Type("autr_2b_null", "let atype = autr_2b in\nlet ltype = stepup in \nlet ftype = null in \n"))
        self.all_types.append(Type("autr_2r_null", "let atype = autr_2r in\nlet ltype = stepup in \nlet ftype = null in \n"))
        self.all_types.append(Type("autr_1b_set", "let atype = autr_1b in\nlet ftype = hasset in \n"))
        self.all_types.append(Type("autr_1r_set", "let atype = autr_1r in\nlet ftype = hasset in \n"))
        self.all_types.append(Type("autr_2b_set", "let atype = autr_2b in\nlet ltype = stepup in \nlet ftype = hasset in \n"))
        self.all_types.append(Type("autr_2r_set", "let atype = autr_2r in\nlet ltype = stepup in \nlet ftype = hasset in \n"))
        

class Auth_1b_em_types(All_types): # types of 1b login phase 
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b_em_set","let atype = autr_1b in\nlet ltype = empty in \nlet ftype = hasset in \n"))
        self.all_types.append(Type("autr_1b_em_null","let atype = autr_1b in\nlet ltype = empty in \nlet ftype = null in \n"))
        

class Auth_1b_st_types(All_types):# types of 1b step-up phase 
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1b_st_set","let atype = autr_1b in\nlet ltype = stepup in \nlet ftype = hasset in \n"))
        self.all_types.append(Type("autr_1b_st_null","let atype = autr_1b in\nlet ltype = stepup in \nlet ftype = null in \n"))

class Auth_1r_em_types(All_types): # types of 1r login phase 
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1r_em_set","let atype = autr_1r in\nlet ltype = empty in \nlet ftype = hasset in \n"))
        self.all_types.append(Type("autr_1r_em_null","let atype = autr_1r in\nlet ltype = empty in \nlet ftype = null in \n"))
        
class Auth_1r_st_types(All_types): # types of 1r step-up phase 
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_1r_st_set","let atype = autr_1r in\nlet ltype = stepup in \nlet ftype = hasset in \n"))
        self.all_types.append(Type("autr_1r_st_null","let atype = autr_1r in\nlet ltype = stepup in \nlet ftype = null in \n"))

class Auth_2b_types(All_types): # types of 2b step-up phase 
    def __init__(self):
        All_types.__init__(self)
        self.all_types.append(Type("autr_2b_set", "let atype = autr_2b in\nlet ltype = stepup in \nlet ftype = hasset in \n"))
        self.all_types.append(Type("autr_2b_null", "let atype = autr_2b in\nlet ltype = stepup in \nlet ftype = null in \n"))

class Auth_2r_types(All_types): # types of 2r step-up phase 
    def __init__(self): 
        All_types.__init__(self)
        self.all_types.append(Type("autr_2r_set", "let atype = autr_2r in\nlet ltype = stepup in \nlet ftype = hasset in \n"))
        self.all_types.append(Type("autr_2r_null", "let atype = autr_2r in\nlet ltype = stepup in \nlet ftype = null in \n"))

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

class Reg_queries(All_queries): # reg queries
    def __init__(self):
        All_queries.__init__(self)
        self.all_queries.append(Query("S-skat", "query secret skAT.\n"))
        self.all_queries.append(Query("Rauth","query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_reg(u,a,aa,kid)) ==> (inj-event(Autr_verify_reg(u,a,aa,kid))==> inj-event(UA_init_reg(u))).\n"))

class Auth_stepup_queries(All_queries): # query of step-up phase 
    def __init__(self):
        All_queries.__init__(self)
        self.all_queries.append(Query("S-tr","query secret testtr.\n"))
        self.all_queries.append(Query("Aauth-tr", "query tr:Tr; inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr))).\n"))

class Auth_1b_em_queries(All_queries): # query of 1b login phase 
    def __init__(self):
        All_queries.__init__(self)
        self.all_queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))

class Auth_1b_st_queries(Auth_stepup_queries):  # query of 1b step-up phase 
    def __init__(self):
        Auth_stepup_queries.__init__(self)
        self.all_queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))


class Auth_2b_queries(Auth_stepup_queries):  # query of 2b step-up phase 
    def __init__(self):
        Auth_stepup_queries.__init__(self)
        self.all_queries.append(Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))

class Auth_1r_em_queries(All_queries):  # query of 1r login phase 
    def __init__(self):
        All_queries.__init__(self)
        self.all_queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))

class Auth_1r_st_queries(Auth_stepup_queries):  # query of 1r step-up phase 
    def __init__(self):
        Auth_stepup_queries.__init__(self)
        self.all_queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))

class Auth_2r_queries(Auth_stepup_queries):  # query of 2r step-up phase 
    def __init__(self):
        Auth_stepup_queries.__init__(self)
        self.all_queries.append(Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))

class All_entities:
    '''
   a parant class for all possible combinations of malicous entities
   you can just write all the possible malicous in subclass for each phase(reg/auth)
   this parant class will generate all the combinations.
   version2 is a reduce plan
    '''
    def __init__(self):
        self.all_entities = []
    def get_all_scenes(self): # a scheme to get all combinations of the entities
        self.entities = []
        for delnum in range(len(self.all_entities) + 1):
            for row_numbers in itertools.combinations(range(len(self.all_entities)), delnum):
                temp = []
                for i in row_numbers:
                    temp.append(self.all_entities[i])
                self.entities.append(Entities(temp,row_numbers))

    def get_all_scenes_version2(self): # another scheme to get less combinations of the entities
        # the rule is to continually add entities which require more ability of the attacker
        # we assume if there is a malicious UC, then there is must a malicious UA.
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



class Reg_entities(All_entities):
    '''
	a class record all possible malicious entities
	use this class, we generate all possible combinations
	'''
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append('RegUS(c, appid, ftype)|\n')
        self.all_entities.append('RegRP(c, https, uname, password)|\n')
        self.all_entities.append("RegUA(https, c, uname ,password,ftype)|\n")
        self.all_entities.append("RegUC(c, MC, fakefacetid, ftype)|\n")
        self.all_entities.append("RegUC(CU, c, facetid, ftype)|\n")
        #self.all_entities.append("RegUC(c, c, fakefacetid, ftype)|\n")
        self.all_entities.append("RegASM(c, AM, token, fakecallerid,fakepersonaid, atype)|\n")
        self.all_entities.append("RegASM(MC, c, token, callerid, personaid, atype)|\n")
        #self.all_entities.append("RegASM(c, c, token, fakecallerid, fakepersonaid, atype)|\n")
        self.all_entities.append("RegAutr(c, aaid, skAT, wrapkey, atype)|\n")
        self.get_all_scenes()

class Reg_entities_version2(All_entities): 
    '''
    do not use,
	another way to insert malicious entities
	in this way, we only consider malicious scenario but not consider who to communicate in this way.
	for example, RegUA | RegASM means there is a malicious UC.
	'''
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("RegUC(c, MC, fakefacetid, ftype)| (*malicious-UA*)\n")
        self.all_entities.append("RegUA(https, c, uname,appid,password,ftype)| RegASM(c, AM, token, fakecallerid, fakepersonaid, atype)| (*malicious-UC*)\n")
        self.all_entities.append("RegUC(CU, c, facetid)| RegAutr(c, aaid, skAT, wrapkey, atype)| (*malicious-ASM*)\n")
        self.all_entities.append("RegASM(MC, c, token, callerid, personaid, atype)| (*-malicious-Autr*)\n")
        self.get_all_scenes()

class Auth_entities(All_entities):
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("AuthUS(c, uname, appid, aaid,kid,pkAU,cntr,tr,ltype,ftype)|\n")
        self.all_entities.append("AuthRP(c, https)|\n")
        self.all_entities.append("AuthUA(https, c,uname, ltype,ftype)|\n")
        self.all_entities.append("AuthUC(c, MC, facetid, ltype,ftype)|\n")
        self.all_entities.append("AuthUC(CU, c, facetid, ltype,ftype)|\n")
        #self.all_entities.append("AuthUC(c, c, fakefacetid, ltype,ftype)|\n")
        self.all_entities.append("AuthASM(c,AM,token,fakecallerid,fakepersonaid,atype,ltype)|\n")
        self.all_entities.append("AuthASM(MC,c,token,callerid,personaid,atype,ltype)|\n")
        #self.all_entities.append("AuthASM(c,c,token,fakecallerid,fakepersonaid,atype,ltype)|\n")
        self.all_entities.append("AuthAutr(c,aaid,wrapkey,cntr,tr,atype,ltype)| \n")
        self.get_all_scenes()

class Auth_entities_version2(All_entities):
    def __init__(self):
        All_entities.__init__(self)
        self.all_entities = []
        self.all_entities.append("AuthUC(c, MC, fakefacetid, ltype)| (*malicious-UA*)\n")
        self.all_entities.append("AuthUA(https, c, uname, ltype)| AuthASM(c,AM,token,fakecallerid,fakepersonaid,atype,ltype)| (*malicious-UC*)\n")
        self.all_entities.append("AuthUC(CU, c, facetid, ltype)| AuthAutr(c,aaid,wrapkey,cntr,tr,atype,ltype)| (*malicious-ASM*)\n")
        self.all_entities.append("AuthASM(MC,c,token,callerid,personaid,atype,ltype)| (*malicious-Autr*)\n")
        self.get_all_scenes()

class All_fields:
    '''
    A parent class for all possible combinations of the compromised fields
    based on the command line parameter, it will choose the "full" version
    to analyze all compromise scenarios of the fields, or the "simple" version
    which do not consider the compromise of the fields.
    '''
    def __init__(self):
        self.all_fields = []
        self.all_fields.append("out(c,token);\n")
        self.all_fields.append("out(c,wrapkey);\n")
    def get_all_scenes(self):
        if Setting.analyze_flag == "simple":
            print("analyzing the scenarios where no fields are comprimised.")
            self.fields = [Fields(["(* no fields being compromised *)\n"],0)]
        else:
            print("analyzing the full scenarios.")
            self.fields = []
            for delnum in range(len(self.all_fields)+ 1) :
                for row_numbers in itertools.combinations(range(len(self.all_fields)), delnum):
                    temp = []
                    for i in row_numbers:
                        temp.append(self.all_fields[i])
                    self.fields.append(Fields(temp,row_numbers))
                    
    def size(self):
        return len(self.fields)
    def get(self,i):
        return self.fields[i]

		
class Reg_fields(All_fields): # particular case in Reg
    def __init__(self):
        All_fields.__init__(self)
        self.all_fields.append("out(c,skAT);\n")
        self.get_all_scenes()

class Auth_fields(All_fields): # paricular case in Auth
    def __init__(self):
        All_fields.__init__(self)
        self.all_fields.append("out(c,skAU);\n")
        self.all_fields.append("out(c,cntr);\n")
        self.all_fields.append("out(c,kid);\n")
        self.get_all_scenes()

class Case:
    '''
    A specific case for analyzing
    phase : registration or authentication
    type : the type of the authenticator
    query : a query
    fields : the fields has been compromised
    entities: the malicous entities scenes
    '''
    def __init__(self,p,t,q,f,e,lines,t_row,i_row):
        self.phase = p # reg or auth
        self.type = t # which authenticator type
        self.query = q # which query
        self.fields = f #which combination of fields
        self.entities = e # which combination of entities
        self.lines = lines # all lines in reg.pv or auth.pv
        self.type_set_row = t_row  # indicate type
        self.insert_row = i_row  # insert line number
        if not os.path.exists("TEMP/"):
            os.makedirs("TEMP/")
        self.query_path = "TEMP/" + "TEMP-" + str(hash(Setting.rootpath + p + t.name + q.name + f.name + e.name)) + ".pv"

    def write_file(self,if_delete_parallel):  #write the query file into query_path for proverif to verify
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

    def analyze(self): # do analysis and get result of proverif
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

    def proverif(self): # activate proverif and analyze the temp .pv file
        output = Popen('proverif -lib "' + Setting.libpath + '" ' + self.query_path, stdout=PIPE, stderr=PIPE)
        timer = Timer(20, lambda process: process.kill(), [output])
        try:
            timer.start()
            stdout, stderr = output.communicate()
            return_code = output.returncode
        finally:
            timer.cancel()
        i = stdout[0:-10].rfind(b'--------------------------------------------------------------') # find last results
        result = stdout[i:-1]
        #print(result)
        if result == b"" or len(result) == 0:
            result = stdout[-1000:-1]
        if (result.find(b'a trace has been found.') != -1):
            ret = 'false'
        elif (result.find(b'trace') != -1):
            ret = 'mayfalse'
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
        return ret, result # return the results



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

    def read_file(self,phase): # read all lines of the reg.pv or auth.pv
        if phase == "reg":
            f = open(Setting.regpath)
            lns = f.readlines()
        elif phase == "auth_1r_em" or phase == "auth_1b_em": 
            f = open(Setting.authpath)
            lns = []
            tttt = f.readlines()
            for i in range(len(tttt)):
            # when it is the longin phase, anyone can communicate with RP
                if i == self.insert_row:
                    lns.append("AuthRP(SR, c)| (*add RP to c for first login*)\n")
                else:
                    lns.append(tttt[i])
        else:
            f = open(Setting.authpath)
            lns = f.readlines()
        f.close()
        return lns


    def generater_case(self): # giving all the input, generate a specific combination as a case
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
                    self.secure_sets.clear()
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
    def reverse_f_e(self): # reverse the fields and entities
        self.fields.fields.reverse()
        self.entities.entities.reverse()
    def this_case_is_secure(self):# add a secure sets
        self.secure_sets.append((self.fields.get(self.f_cur).row_numbers, self.entities.get(self.e_cur).row_numbers))
    def jump_if_its_secure(self):
        for secure_case in self.secure_sets:
            cur_f_case = self.fields.get(self.f_cur).row_numbers
            cur_e_case = self.entities.get(self.e_cur).row_numbers
            if(set(cur_f_case).issubset(set(secure_case[0]))) and (set(cur_e_case).issubset(set(secure_case[1]))):
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
    gen = Generator(phase) # instance of the generator to generate a case
    count = 0
    while True:
        r, case = gen.generater_case() # get a case to analyze
        if r == False: # end mark
            print(phase + " is finish !!!!!!!!!!")
            break
        log_msg = str(count).ljust(6)
        write_name = str(count).ljust(6)
        if(gen.jump_if_its_secure()): # jump analyzing if it take a secure case as the subset
            log_msg += phase.ljust(4) + "  skipping for secure sets"
        elif(gen.jump_if_its_noprove()): # jump analyzing if it take a un-prove case as the subset
            log_msg += phase.ljust(4) + "  skipping for noprove sets"
        else: # no jumping and continually analyze
            log_msg += phase.ljust(4)
            ret, result, content = case.analyze() # analyze this case
            if ret == 'true':
                gen.this_case_is_secure()
                log_msg += " true"
                write_name += " true"
            else:
                log_msg += " " + ret # generate all the message
                write_name += " " + ret
            log_msg += " type "
            log_msg += case.type.name.ljust(4)
            log_msg += " query "
            log_msg += case.query.name.ljust(4)
            log_msg += " "
            log_msg += str(case.fields.name).ljust(9)
            write_name += " "
            write_name += str(case.fields.name).ljust(9)
            log_msg += " "
            log_msg += str(case.entities.name).ljust(8)
            log_msg += " "
            log_msg += time.strftime('%Y.%m.%d %H:%M ',time.localtime(time.time()))
            write_name += " "
            write_name += str(case.entities.name).ljust(9)
            if ret != 'false' and ret != 'prove':  #  if not false then write the result file
                if not os.path.exists(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name):
                    os.makedirs(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name)
                f = open(Setting.resultpath + case.phase + "/" + case.type.name + "/" + case.query.name + "/" + write_name, "w")
                f.writelines(content)
                f.writelines(str(result[-1000:-1]))
                f.close()
        count = count + 1
        write_log(log_msg, log)
        log.flush()

def write_log(msg,log): # definition of how to write a log file
    print(msg, file = log)

def print_help():
    print("usage: [-help] [-h] [-target <target_name>] [-t <target_name>]")
    print("Options and arguments:")
    print("-h/-help  : show help informations.")
    print("-s/-simple :  analyze cases where the fields are not leaked, this argument will reduce the analyzing time but give incomplete results. If don't specify, then analyze all cases.")
    print("-t/-target  : verify a specific phase, if don't specify, then verify all phases. ")
    print("    The candidates arguments are:")
    print("       reg   : to analyze registration process.")
    print("       auth_1b_em   : to analyze authentication process with 1B authenticator to log in.")
    print("       auth_1b_st   : to analyze authentication process with 1B authenticator to step-up authentication.")
    print("       auth_1r_em   : to analyze authentication process with 1R authenticator to log in.")
    print("       auth_1r_st   : to analyze authentication process with 1R authenticator to step-up authentication.")
    print("       auth_2b   : to analyze authentication process with 2B authenticator to step-up authentication.")
    print("       auth_2r   : to analyze authentication process with 2R authenticator to step-up authentication.")


if __name__ == "__main__":
    Setting.initiate() #initiate the setting and ensure the environment is ready
    log1 = open(Setting.logpath1, mode='w+', encoding='utf-8')  # open the log file to write
    log2 = open(Setting.logpath2, mode='w+', encoding='utf-8')
    log3 = open(Setting.logpath3, mode='w+', encoding='utf-8')
    log4 = open(Setting.logpath4, mode='w+', encoding='utf-8')
    log5 = open(Setting.logpath5, mode='w+', encoding='utf-8')
    log6 = open(Setting.logpath6, mode='w+', encoding='utf-8')
    log7 = open(Setting.logpath7, mode='w+', encoding='utf-8')
    t1 = threading.Thread(target=analysis, args=("reg", log1))  # create threads for each phase
    t2 = threading.Thread(target=analysis, args=("auth_1b_em", log2))
    t3 = threading.Thread(target=analysis, args=("auth_1b_st", log3))
    t4 = threading.Thread(target=analysis, args=("auth_1r_em", log4))
    t5 = threading.Thread(target=analysis, args=("auth_1r_st", log5))
    t6 = threading.Thread(target=analysis, args=("auth_2b", log6))
    t7 = threading.Thread(target=analysis, args=("auth_2r", log7))
    tlist = [t1,t2,t3,t4,t5,t6,t7]  #run all th phase
    try:
        options, args = getopt.getopt(sys.argv[1:], "-h-help-t:-target:-s-simple", ["help", "target="])
    except getopt.GetoptError:
        print("wrong option!")
        print_help()
        sys.exit()
    for option, value in options:
        if option in ("-h", "-help", "--help"):
            print_help()
            sys.exit()
        elif option in ("-t","--t","--target","-target"): # if specific which phase to analyze, then clean the tlist
            tlist = []
            if str(value) == "reg":
                tlist.append(t1)
            elif str(value) == "auth_1b_em":
                tlist.append(t2)
            elif str(value) == "auth_1b_st":
                tlist.append(t3)
            elif str(value) == "auth_1r_em":
                tlist.append(t4)
            elif str(value) == "auth_1r_st":
                tlist.append(t5)
            elif str(value) == "auth_2b":
                tlist.append(t6)
            elif str(value) == "auth_2r":
                tlist.append(t7)
            else:
                print("wrong arguemnt!")
        elif option in ("-simple", "-s"):
            Setting.analyze_flag = "simple"
        else:
            print("wrong option!")
    for t in tlist:
        t.start()
    for t in tlist:
        t.join()
    log1.close()
    log2.close()
    log3.close()
    log4.close()
    log5.close()
