import copy
import os
import itertools
from Definition import Query

class Reg():
    '''
    生成注册阶段.pv文件文本的类，需要其他类辅助生成
    '''
    def __init__(self):
        self.content = ["let system(appid:Appid,aaid:AAID,skAT:sskey,uname:Uname,password:bitstring,facetid:Facetid,callerid:Callerid,personaid:PersonaID,token:bitstring,wrapkey:key)=\n" ,
                        "(\n" ,
                        "\tnew SR:channel; new https:channel; new CU:channel; new MC:channel; new AM:channel;\n" ,
                        "\tlet pkAT = spk(skAT) in\n",
                        "\tnew skAUbasic:sskey; new cntrbasic:CNTR; new kidbasic:KeyID;\n" ,
                        "\tnew fakefacetid:Facetid; new fakecallerid:Callerid; new fakepersonaid:PersonaID;\n" ,
                        "\t(* the attacker has access to following fields *)\n" ,
                        "\tout(c,(uname,appid,facetid,callerid,fakefacetid,personaid,fakepersonaid,aaid,pkAT));\n" ,
                        "\tinsert AppList(appid,facetid);\n",
                        "\t(event leak_token();out(c,token))|\n",
                        "\t(event leak_kw(); out(c,wrapkey))|\n",
                        "\t(event leak_skat(); out(c,skAT))|\n",
                        "\t(event malicious_US_to_RP();!RegRP_(c, https, uname, password))|\n",
                        "\t(event malicious_RP_to_US();!RegUS_(c, appid))|\n",
                        "\t(event malicious_RP_to_UA(); RegUA_(c,CU,uname,password))|\n",
                        "\t(event malicious_UA_to_RP(); !RegRP_(SR, c, uname, password))|\n",
                        "\t(event malicious_UA_to_UC();!RegUC_(c, MC, fakefacetid))|\n",
                        "\t(event malicious_UC_to_UA();RegUA_(https, c, uname,password))|\n",
                        "\t(event malicious_UC_to_ASM();!RegASM_(c, AM, token, fakecallerid, fakepersonaid))|\n",
                        "\t(event malicious_ASM_to_UC();!RegUC_(CU, c, facetid))|\n",
                        "\t(event malicious_ASM_to_Autr();!RegAutr_(c, aaid, skAT, wrapkey,skAUbasic,cntrbasic,kidbasic))|\n",
                        "\t(event malicious_Autr_to_ASM();!RegASM_(MC, c, token, callerid, personaid))|\n",
                        "\tRegUS_(SR, appid)|\n",
                        "\tRegRP_(SR, https, uname, password)|\n",
                        "\tRegUA_(https, CU,uname, password)|\n",
                        "\tRegUC_(CU, MC, facetid)|\n",
                        "\tRegASM_(MC, AM, token, callerid, personaid)|\n",
                        "\tRegAutr_(AM, aaid, skAT, wrapkey,skAUbasic,cntrbasic,kidbasic)\n" ,
                        ").\n" ,
                        "process\n" ,
                        "( \n" ,
                        "\tnew appid:Appid; new aaid:AAID; new facetid:Facetid;  new callerid:Callerid;  new personaid:PersonaID; new skAT:sskey;  new wrapkey:key; new token:bitstring;\n" ,
                        "\tnew uname:Uname; new password:bitstring;\n" ,
                        "\t(* User 1 registers in RP 1 *)\n" ,
                        "\tsystem(appid,aaid,skAT,uname,password,facetid,callerid,personaid,token,wrapkey)\n"
                        ")\n"]
        self.basic_queries = [Query("s-skau","query seed:bitstring; ","attacker(gen_skAU(new skAUbasic,seed))"),
                            Query("s-ak","query ","attacker(To_12b_token(new appid,new token,new callerid,new personaid))"),
                            Query("s-cntr","query seed:bitstring;","attacker(gen_cntr(new cntrbasic,seed))"),
                            Query("S-skat", "query ","attacker(new skAT)"),
                            Query("Rauth","query u:Uname,a:Appid,aa:AAID,kid:KeyID; ","inj-event(RP_success_reg(u,a,aa,kid)) ==> (inj-event(Autr_verify_reg(u,a,aa,kid))==> inj-event(UA_init_reg(u)))")]
        self.query_test = ["event(leak_token())",
                           "event(leak_kw())",
                           "event(leak_skat())",
                           "event(malicious_US_to_RP())",
                           "event(malicious_RP_to_US())",
                           "event(malicious_RP_to_UA())",
                           "event(malicious_UA_to_RP())",
                           "event(malicious_UA_to_UC())",
                           "event(malicious_UC_to_UA())",
                           "event(malicious_UC_to_ASM())",
                           "event(malicious_ASM_to_UC())",
                           "event(malicious_ASM_to_Autr())",
                           "event(malicious_Autr_to_ASM())"]
        self.all_queries = []
        self.if_set_type = False
        self.need_type_row = 12
        self.need_type_num = 16

    def set_type(self,type):
        for i in range(self.need_type_num):  # 每行的指定位置加入类型字段，如
            index = self.content[self.need_type_row + i].rindex("_") + 1
            list_str = list(self.content[self.need_type_row + i])
            list_str.insert(index, type)
            self.content[self.need_type_row + i] = "".join(list_str)
        self.if_set_type = True
    def get_all_queries(self):
        for query in self.basic_queries:#遍历所有的基本询问语句
            for num in range(len(self.query_test) + 1): #遍历每种增加的个数
                for events in itertools.combinations((self.query_test), num):#遍历每种num数量下的event
                    query_temp = query.query
                    if query.query.find("==>") == -1 and num != 0:  # 机密性询问
                        query_temp += "==>"
                    for event in events:#遍历每个event，增加
                        if query_temp[-1] == ">":
                            query_temp += event
                        else:
                            query_temp += "||" + event
                    query_temp += ".\n"
                    self.all_queries.append(query_temp)
    def get_group_queries(self):
        for query in self.basic_queries:#遍历所有的基本询问语句
            self.all_queries.append(query.head)
            for num in range(len(self.query_test) + 1): #遍历每种增加的个数
                for events in itertools.combinations((self.query_test), num):#遍历每种num数量下的event
                    query_temp = query.content
                    if query_temp.find("==>") == -1 and num != 0:  # 机密性询问
                        query_temp += "==>"
                    for event in events:#遍历每个event，增加
                        if query_temp[-1] == ">":
                            query_temp += event
                        else:
                            query_temp += "||" + event
                    query_temp += ";\n"
                    self.all_queries.append(query_temp)
            index = self.all_queries[-1].rindex(";")
            list_str = list(self.all_queries[-1])
            list_str[index] = "."
            self.all_queries[-1] = "".join(list_str) #set last ; to .
    def write_content(self):
        with open(os.getcwd() + "/" + "Query/" + self.scene_name + ".pv", "w") as f:
            f.writelines(self.all_queries)
            f.writelines(self.content)
    def get_file_name(self):
        return os.getcwd() + "/" + "Query/" + self.scene_name + ".pv"

class Reg_1b_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1b_seta"
        self.set_type("1b_seta")
        self.basic_queries.append(Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()
        self.write_content()

class Reg_1b_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1b_noa"
        self.set_type("1b_noa")
        self.basic_queries.append(Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()
        self.write_content()

class Reg_2b_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2b_seta"
        self.set_type("2b_seta")
        self.basic_queries.append(Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()
        self.write_content()

class Reg_2b_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2b_noa"
        self.set_type("2b_noa")
        self.basic_queries.append(Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()
        self.write_content()

class Reg_1r_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1r_seta"
        self.set_type("1r_seta")
        self.basic_queries.append(Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()
        self.write_content()

class Reg_1r_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1r_noa"
        self.set_type("1r_noa")
        self.basic_queries.append(Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()
        self.write_content()

class Reg_2r_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2r_seta"
        self.set_type("2r_seta")
        self.basic_queries.append(Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(senc((gen_skAU(new skAUbasic,seed),ak),new wrapkey))"))
        self.get_group_queries()
        self.write_content()

class Reg_2r_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2r_noa"
        self.set_type("2r_noa")
        self.basic_queries.append(Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(senc((gen_skAU(new skAUbasic,seed),ak),new wrapkey))"))
        self.get_group_queries()
        self.write_content()

class Auth_content():
    def __init__(self):
        self.content = ["let system(appid:Appid,aaid:AAID,skAU:sskey,keyid:KeyID,wrapkey:key,token:bitstring,uname:Uname,facetid:Facetid,callerid:Callerid,personaid:PersonaID,cntr:CNTR) =\n",
                        "((* one RP authenticate one user many times *)\n",
                        "	let pkAU = spk(skAU) in let testskAU = skAU in let testcntr = cntr in\n",
                        "	out(c,(uname,appid,facetid,aaid,callerid,personaid,pkAU)); (* public info *)\n",
                        "	( \n",
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
                        "	system(appid,aaid,skAU,keyid,wrapkey,token,uname,facetid,callerid,personaid,cntr)|\n",
                        "	(* User 2 authenticates in RP 1 *)\n",
                        "	(\n",
                        "		new skAU2:sskey; new keyid2:KeyID; new wrapkey2:key; new token2:bitstring; new uname2:Uname; new cntr2:CNTR;\n",
                        "		system(appid,aaid,skAU2,keyid2,wrapkey2,token2,uname2,facetid,callerid,personaid,cntr2)\n",
                        "	)|\n",
                        "	(* User 1 authenticates in RP 2 *)\n",
                        "	(\n",
                        "		new appid2:Appid; new skAU3:sskey; new keyid3:KeyID; new uname3:Uname; new cntr3:CNTR;\n",
                        "		system(appid2,aaid,skAU3,keyid3,wrapkey,token,uname3,facetid,callerid,personaid,cntr3)\n",
                        "	)\n",
                        ")\n"]
        self.insert_number = 12
        self.specific_operation_insert_number = 8