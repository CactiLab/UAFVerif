import itertools
import os
import sys
import threading
import getopt
import time
from threading import Timer
from subprocess import Popen, PIPE

class Reg_content():
    '''
    生成注册阶段.pv文件文本的类，需要其他类辅助生成
    '''
    def __init__(self):
        self.content = ["let system(appid:Appid,aaid:AAID,skAT:sskey,uname:Uname,password:bitstring,facetid:Facetid,callerid:Callerid,personaid:PersonaID,token:bitstring,wrapkey:key)=\n" ,
                        "(\n" ,
                        "   new SR:channel; new https:channel; new CU:channel; new MC:channel; new AM:channel;\n" ,
                        "   let pkAT = spk(skAT) in\n" ,
                        "   new fakefacetid:Facetid; new fakecallerid:Callerid; new fakepersonaid:PersonaID;\n" ,
                        "   (* the attacker has access to following fields *)\n" ,
                        "   out(c,(uname,appid,facetid,callerid,fakefacetid,fakecallerid,fakepersonaid,aaid,pkAT));\n" ,
                        "   insert AppList(appid,facetid);\n" ,
                        ").\n" ,
                        "process\n" ,
                        "( \n" ,
                        "	(\n" ,
                        "	new appid:Appid; new aaid:AAID; new facetid:Facetid;  new callerid:Callerid;  new personaid:PersonaID; new skAT:sskey;  new wrapkey:key; new token:bitstring;\n" ,
                        "   new uname:Uname; new password:bitstring;\n" ,
                        "   (* User 1 registers in RP 1 *)\n" ,
                        "   !system(appid,aaid,skAT,uname,password,facetid,callerid,personaid,token,wrapkey)|\n"
                        "   !(\n" ,
                        "   (* User 2 registers in RP 1*)\n" ,
                        "			new uname2:Uname;\n" ,
                        "			new password2:bitstring;\n" ,
                        "			new token2:bitstring;\n" ,
                        "			new wrapkey2:key;\n" ,
                        "			system(appid,aaid,skAT,uname2,password2,facetid,callerid,personaid,token2,wrapkey2)\n" ,
                        "		)|\n" ,
                        "		(* User 1 registers in RP 2, we assume the same user will not use same UName and pwd in different RPs*)\n" ,
                        "		!(\n" ,
                        "			new appid2:Appid;\n" ,
                        "			new uname3:Uname;\n" ,
                        "			new password3:bitstring;\n" ,
                        "			system(appid2,aaid,skAT,uname3,password3,facetid,callerid,personaid,token,wrapkey)\n" ,
                        "		)\n" ,
                        "	)\n" ,
                        ")\n"]
        self.insert_number = 8
        self.if_add = -3
    def add_query(self, query, query_name):
        self.content.insert(0,query)
        self.if_add = self.if_add + 1
        self.query_name = query_name
    def add_honest_entities(self, honest_entities, scene_name):
        for line in honest_entities:
            self.content.insert(self.insert_number, line)
            self.insert_number += 1
        self.insert_number = 8
        self.if_add = self.if_add + 1
        self.scene_name = scene_name
    def add_leak_fields(self, leak_fields, leak_lines):
        for line in leak_fields:
            self.content.insert(self.insert_number,line)
            self.insert_number += 1
        self.if_add = self.if_add + 1
        self.leak_lines = leak_lines
        self.leak_lines_write = ""
        for i in self.leak_lines:
            self.leak_lines_write += str(i) + " "
    def add_malicious_entities(self, malicious_entities,malicious_lines):
        for line in malicious_entities:
            self.content.insert(self.insert_number, line)
            self.insert_number += 1
        self.if_add = self.if_add + 1
        self.malicious_lines = malicious_lines
        self.malicious_lines_write = ""
        for i in self.malicious_lines:
            self.malicious_lines_write += str(i) + " "
    def get_content(self):
        if self.if_add < 0:
            print("error, the content is not completed, check the code")
            exit(-1)
        return self.content


class Query:
    def __init__(self,name,query):
        self.name = name
        self.query = query

class Reg:
    def __init__(self):
        self.honest_entities = ["(SR, appid)|\n",
                                "(SR, https, uname, password)|\n",
                                "(SR, c, uname, password)|\n",
                                "(https, CU,uname, password)|\n",
                                "(CU, MC, facetid)|\n",
                                "(MC, AM, token, callerid, personaid)|\n",
                                "(AM, aaid, skAT, wrapkey)\n"]
        self.malicious_entities = ["(c, appid)|\n",
                                   "(c, https, uname, password)|\n",
                                   "(https, c, uname,password)|\n",
                                   "(c, MC, fakefacetid)|\n",
                                   "(CU, c, facetid)|\n",
                                   "(c, AM, token, fakecallerid, fakepersonaid)|\n",
                                   "(MC, c, token, callerid, personaid)|\n",
                                   "(c, aaid, skAT, wrapkey)|\n"]
        self.leak_fields = ["out(c,token);\n",
                            "out(c,wrapkey);\n",
                            "out(c,skAT);\n"]
        self.queries = [Query("s-ak","query secret testak.\n"),
                        Query("s-cntr","query secret testcntr.\n"),
                        Query("s-skau","query secret testskAU.\n"),
                        Query("s-kid","query secret testkid.\n")]
    def complete_content(self,honest_name,malicious_name):
        for i in range(len(self.honest_entities)):
            self.honest_entities[i] = honest_name[i] + self.honest_entities[i]
        for i in range(len(self.malicious_entities)):
            self.malicious_entities[i] = malicious_name[i] + self.malicious_entities[i]
    def get_honest_entities(self):
        return self.honest_entities
    def get_malicious_entities(self):
        return self.malicious_entities
    def get_leak_fields(self):
        return self.leak_fields
    def get_queries(self):
        return self.queries



class Reg_1b_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1b_seta"
        honest_name = ["RegUS_seta","RegRP","RegRP","RegUA_seta","RegUC_seta","RegASM_1b2b","RegAutr_1b"]
        malicious_name = ["RegUS_seta","RegRP","RegUA_seta","RegUC_seta","RegUC_seta","RegASM_1b2b","RegASM_1b2b","RegAutr_1b"]
        self.complete_content(honest_name,malicious_name)

class Reg_1b_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1b_noa"
        honest_name = ["RegUS_noa","RegRP","RegRP","RegUA_noa","RegUC_noa","RegASM_1b2b","RegAutr_1b"]
        malicious_name = ["RegUS_noa","RegRP","RegUA_noa","RegUC_noa","RegUC_noa","RegASM_1b2b","RegASM_1b2b","RegAutr_1b"]
        self.complete_content(honest_name,malicious_name)

class Reg_2b_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2b_seta"
        honest_name = ["RegUS_seta","RegRP","RegRP","RegUA_seta","RegUC_seta","RegASM_1b2b","RegAutr_2b"]
        malicious_name = ["RegUS_seta","RegRP","RegUA_seta","RegUC_seta","RegUC_seta","RegASM_1b2b","RegASM_1b2b","RegAutr_2b"]
        self.complete_content(honest_name,malicious_name)

class Reg_2b_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        scene_name = "Reg_2b_noa"
        honest_name = ["RegUS_noa","RegRP","RegRP","RegUA_noa","RegUC_noa","RegASM_1b2b","RegAutr_2b"]
        malicious_name = ["RegUS_noa","RegRP","RegUA_noa","RegUC_noa","RegUC_noa","RegASM_1b2b","RegASM_1b2b","RegAutr_2b"]
        self.complete_content(honest_name,malicious_name)

class Reg_1r_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1r_seta"
        honest_name = ["RegUS_seta","RegRP","RegRP","RegUA_seta","RegUC_seta","RegASM_1r2r","RegAutr_1r"]
        malicious_name = ["RegUS_seta","RegRP","RegUA_seta","RegUC_seta","RegUC_seta","RegASM_1r2r","RegASM_1r2r","RegAutr_1r"]
        self.complete_content(honest_name,malicious_name)
class Reg_1r_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1r_noa"
        honest_name = ["RegUS_noa","RegRP","RegRP","RegUA_noa","RegUC_noa","RegASM_1r2r","RegAutr_1r"]
        malicious_name = ["RegUS_noa","RegRP","RegUA_noa","RegUC_noa","RegUC_noa","RegASM_1r2r","RegASM_1r2r","RegAutr_1r"]
        self.complete_content(honest_name,malicious_name)
class Reg_2r_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2r_seta"
        honest_name = ["RegUS_seta","RegRP","RegRP","RegUA_seta","RegUC_seta","RegASM_1r2r","RegAutr_2r"]
        malicious_name = ["RegUS_seta","RegRP","RegUA_seta","RegUC_seta","RegUC_seta","RegASM_1r2r","RegASM_1r2r","RegAutr_2r"]
        self.complete_content(honest_name,malicious_name)
class Reg_2r_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2r_noa"
        honest_name = ["RegUS_noa","RegRP","RegRP","RegUA_noa","RegUC_noa","RegASM_1r2r","RegAutr_2r"]
        malicious_name = ["RegUS_noa","RegRP","RegUA_seta","RegUC_noa","RegUC_noa","RegASM_1r2r","RegASM_1r2r","RegAutr_2r"]
        self.complete_content(honest_name,malicious_name)

class Generator:
    def __init__(self,content_class,target_scene):
        self.content_class = content_class
        self.target_scene = target_scene
        self.all_leak = []
        self.all_malicious = []
        self.all_queries = target_scene.get_queries()
        for delnum in range(len(target_scene.get_leak_fields()) + 1):
            for row_numbers in itertools.combinations(range(len(target_scene.get_leak_fields())), delnum):
                temp = []
                for i in row_numbers:
                    temp.append(target_scene.get_leak_fields()[i])
                self.all_leak.append((row_numbers,temp))
        for delnum in range(len(target_scene.get_malicious_entities()) + 1):
            for row_numbers in itertools.combinations(range(len(target_scene.get_malicious_entities())), delnum):
                temp = []
                for i in row_numbers:
                    temp.append(target_scene.get_malicious_entities()[i])
                self. all_malicious.append((row_numbers,temp))
        self.all_malicious.reverse()
        self.all_leak.reverse()
        self.query_num = len(self.all_queries)
        self.leak_num = len(self.all_leak)
        self.malicious_num = len(self.all_malicious)
        self.cur_q = 0
        self.cur_l = 0
        self.cur_m = -1
    def generate_case(self):
        target_content = self.content_class()
        if self.cur_m >= self.malicious_num - 1:
            self.cur_m = 0
            if(self.cur_l >= self.leak_num - 1):
                self.cur_l = 0
                if(self.cur_q >= self.query_num - 1):
                    return False, target_content
                else:
                    self.cur_q = self.cur_q + 1
            else:
                self.cur_l = self.cur_l + 1
        else:
            self.cur_m = self.cur_m + 1
        target_content.add_honest_entities(self.target_scene.get_honest_entities(), self.target_scene.scene_name)
        target_content.add_leak_fields(self.all_leak[self.cur_l][1],self.all_leak[self.cur_l][0])
        target_content.add_malicious_entities(self.all_malicious[self.cur_m][1],self.all_malicious[self.cur_m][0])
        target_content.add_query(self.all_queries[self.cur_q].query, self.all_queries[self.cur_q].name)
        return True, target_content

class Auth_content():
    def __init__(self):
        self.content = ["let system(appid:Appid,aaid:AAID,skAU:sskey,keyid:KeyID,wrapkey:key,token:bitstring,uname:Uname,facetid:Facetid,callerid:Callerid,personaid:PersonaID,cntr:CNTR) =\n",
                        "((* one RP authenticate one user many times *)\n",
                        "	let pkAU = spk(skAU) in let testskAU = skAU in\n",
                        "	let kh = get_kh(atype,uname,appid,callerid,personaid,token,keyid,wrapkey,skAU) in\n",
                        "	let kid = get_kid(atype,kh,keyid) in let testkid = kid in	\n",
                        "	insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);\n",
                        "	out(c,(uname,appid,facetid,aaid,callerid,personaid,pkAU)); (* public info *)\n",
                        "	( ",
                        "		new SR:channel; new https:channel; new CU:channel; new MC:channel; new AM:channel;\n",
                        "		new fakecallerid:Callerid; new fakefacetid:Facetid; new fakepersonaid:PersonaID;\n",
                        "		new tr:Tr;   let testtr = tr in\n",
                        "	)\n",
                        ").\n",
                        "process\n",
                        "(\n",
                        "	new appid:Appid; new aaid:AAID; new skAU:sskey;  new keyid:KeyID; new wrapkey:key;	 new token:bitstring; new uname:Uname; new cntr:CNTR;\n",
                        "	new facetid:Facetid; insert AuthAppList(appid,facetid);\n",
                        "	new callerid:Callerid; insert TrustCallerid(callerid);\n",
                        "	new personaid:PersonaID;\n",
                        "	(* User 1 authenticates in RP 1 *)\n",
                        "	!system(appid,aaid,skAU,keyid,wrapkey,token,uname,facetid,callerid,personaid,cntr)|\n",
                        "	(* User 2 authenticates in RP 1 *)\n",
                        "	!(\n",
                        "				new skAU2:sskey; new keyid2:KeyID; new wrapkey2:key; new token2:bitstring; new uname2:Uname; new cntr2:CNTR;\n",
                        "		system(appid,aaid,skAU2,keyid2,wrapkey2,token2,uname2,facetid,callerid,personaid,cntr2)\n",
                        "	)|\n",
                        "	(* User 1 authenticates in RP 2 *)\n",
                        "	!(\n",
                        "		new appid2:Appid; new skAU3:sskey; new keyid3:KeyID; new uname3:Uname; new cntr3:CNTR;\n",
                        "		system(appid2,aaid,skAU3,keyid3,wrapkey,token,uname3,facetid,callerid,personaid,cntr3)\n",
                        "	)\n",
                        ")\n"]
        self.insert_number = 8
        self.if_add = -3
    def add_query(self, query, query_name):
        self.content.insert(0, query)
        self.if_add = self.if_add + 1
    def add_honest_entities(self, honest_entities, scene):
        for line in honest_entities:
            self.content.insert(self.insert_number, line)
        self.if_add = self.if_add + 1
    def add_malicious_entities(self, malicious_entities, mark):
        for line in malicious_entities:
            self.content.insert(self.insert_number, line)
        self.if_add = self.if_add + 1
    def get_content(self):
        if self.if_add < 0:
            print("error, the content is not completed, check the code")
            exit(-1)
        return self.content

def proverif(root_path,query_path): # activate proverif and analyze the temp .pv file
    output = Popen('proverif -lib "' + root_path + "UAF.pvl" + '" ' + query_path, stdout=PIPE, stderr=PIPE)
    timer = Timer(20, lambda process: process.kill(), [output])
    try:
        timer.start()
        stdout, stderr = output.communicate()
        return_code = output.returncode
    finally:
        timer.cancel()
    i = stdout[0:-10].rfind(b'--------------------------------------------------------------') # find last results
    result = stdout[i:-1]
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
    return ret, result # return the results

class Jump:
    def __init__(self):
        self.secure_set = []
    def add_secure_scene(self,target_scene):
        self.secure_set.append(target_scene)
    def is_secure(self,target_scene):
        for secure_scene in self.secure_set:
            if secure_scene.scene_name == target_scene.scene_name and secure_scene.query_name == target_scene.query_name:
                if (set(target_scene.leak_lines).issubset(set(secure_scene.leak_lines))) and (set(target_scene.malicious_lines).issubset(set(target_scene.malicious_lines))):
                    return True
        return False

def analyze(root_path,content_class,target_scene):
    if not os.path.exists(root_path + "/" + "RESULT/"):
        os.makedirs(root_path + "/" + "RESULT/")
    if not os.path.exists(root_path + "/" + "TEMP/"):
        os.makedirs(root_path + "/" + "TEMP/")
    if not os.path.exists(root_path + "/" + "LOG/"):
        os.makedirs(root_path + "/" + "LOG/")
    gen = Generator(content_class,target_scene)
    jump = Jump()
    log_file = open(root_path + "/LOG/" + target_scene.scene_name + ".log","w")
    count = 0
    while True:
        state, gen_content = gen.generate_case()
        if state == False:
            break
        log_msg = str(count).ljust(6)
        if jump.is_secure(gen_content):
            log_msg += "  skipping for secure sets"
        else:
            content = gen_content.get_content()
            temp_pvfile_path = root_path + "/TEMP/" + target_scene.scene_name + "temp.pv"
            f = open(temp_pvfile_path,"w")
            f.writelines(content)
            f.close()
            ret, result = proverif(root_path, temp_pvfile_path)
            if ret == 'true':
                jump.add_secure_scene(gen_content)
            log_msg += "  " + str(ret)
            log_msg += " TYPE "
            log_msg += gen_content.scene_name.ljust(6)
            log_msg += " QUERY "
            log_msg += gen_content.query_name.ljust(4)
            log_msg += " LEAK "
            log_msg += gen_content.leak_lines_write.ljust(5)
            log_msg += " MALICIOUS "
            log_msg += gen_content.malicious_lines_write.ljust(8)
            file_log_write = log_msg
            log_msg += " TIME "
            log_msg += time.strftime('%Y.%m.%d %H:%M ', time.localtime(time.time()))
            if ret != 'false' and ret != 'prove':  #  if not false then write the result file
                if not os.path.exists(root_path + "/" + "RESULT/" + gen_content.scene_name + "/" + gen_content.query_name):
                    os.makedirs(root_path + "/" + "RESULT/" + gen_content.scene_name + "/" + gen_content.query_name)
                f = open(root_path + "/" + "RESULT/" + gen_content.scene_name + "/" + gen_content.query_name + "/" + file_log_write, "w")
                f.writelines(content)
                f.writelines(str(result[-1000:-1]))
                f.close()
        count = count + 1
        print(log_msg, file = log_file)
        log_file.flush()
    log_file.close()


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
    root_path = os.getcwd() + "/"
    reg_1b_seta = Reg_1b_seta()
    reg_1b_noa = Reg_1b_noa()
    reg_2b_seta = Reg_2b_seta()
    reg_2b_noa = Reg_2b_noa()
    reg_1r_seta = Reg_1r_seta()
    reg_1r_noa = Reg_1r_noa()
    reg_2r_seta = Reg_2r_seta()
    reg_2r_noa = Reg_2r_noa()
    regt1 = threading.Thread(target=analyze, args=(root_path, Reg_content,reg_1b_seta))  # create threads for each phase
    regt2 = threading.Thread(target=analyze, args=(root_path, Reg_content,reg_1b_noa))
    regt3 = threading.Thread(target=analyze, args=(root_path, Reg_content,reg_2b_seta))
    regt4 = threading.Thread(target=analyze, args=(root_path, Reg_content,reg_2b_noa))
    regt5 = threading.Thread(target=analyze, args=(root_path, Reg_content,reg_1r_seta))
    regt6 = threading.Thread(target=analyze, args=(root_path, Reg_content,reg_1r_noa))
    regt7 = threading.Thread(target=analyze, args=(root_path, Reg_content,reg_2r_seta))
    regt8 = threading.Thread(target=analyze, args=(root_path, Reg_content, reg_2r_noa))
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
        elif option in ("-t", "--t", "--target", "-target"):  # if specific which phase to analyze, then clean the tlist
            tlist = []
            if str(value) == "reg":
                tlist.append(regt1)
            elif str(value) == "auth_1b_em":
                tlist.append(regt2)
            elif str(value) == "auth_1b_st":
                tlist.append(regt3)
            elif str(value) == "auth_1r_em":
                tlist.append(regt4)
            elif str(value) == "auth_1r_st":
                tlist.append(regt5)
            elif str(value) == "auth_2b":
                tlist.append(regt6)
            elif str(value) == "auth_2r":
                tlist.append(regt7)
            else:
                print("wrong arguemnt!")
    regt1.start()
    regt1.join()