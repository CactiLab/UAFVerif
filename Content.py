import copy
import os
import itertools
from Definition import Basic_Query,Query

class Content:
    def set_type(self,type):
        for i in range(self.need_type_num):  # 每行的指定位置加入类型字段，如
            index = self.content[self.need_type_row + i].rindex("_") + 1
            list_str = list(self.content[self.need_type_row + i])
            list_str.insert(index, type)
            self.content[self.need_type_row + i] = "".join(list_str)
        self.if_set_type = True
    def get_all_queries(self):
        for basic_query in self.basic_queries:#遍历所有的基本询问语句
            for num in range(len(self.query_test) + 1): #遍历每种增加的个数
                for events in itertools.combinations((self.query_test), num):#遍历每种num数量下的event
                    query_temp = basic_query.content
                    if basic_query.content.find("==>") == -1 and num != 0:  # 机密性询问
                        query_temp += "==>"
                    for event in events:#遍历每个event，增加
                        if query_temp[-1] == ">":
                            query_temp += event
                        else:
                            query_temp += "||" + event
                    query_temp += ".\n"
                    self.all_queries.append(Query(self.scene_name,basic_query.name,query_temp,events))
    def get_group_queries(self):
        for basic_query in self.basic_queries:#遍历所有的基本询问语句
            #if basic_query.name.find("auth") == -1: #secrecy properties
            if True:
                temp_group_query = basic_query.head + "\n"
                for num in range(len(self.query_test) + 1): #遍历每种增加的个数
                    for events in itertools.combinations((self.query_test), num):#遍历每种num数量下的event
                        query_temp = basic_query.body
                        if query_temp.find("==>") == -1 and num != 0:  # 机密性询问
                            query_temp += "==>"
                        for event in events:#遍历每个event，增加
                            if query_temp[-1] == ">":
                                query_temp += event
                            else:
                                query_temp += "||" + event
                        query_temp += ";\n"
                        temp_group_query += query_temp
                index = temp_group_query.rindex(";")
                list_str = list(temp_group_query)
                list_str[index] = "."
                temp_group_query = "".join(list_str) #set last ; to .
                self.all_queries.append(Query(self.scene_name,basic_query.name,temp_group_query,[]))
            else:#authentication properties
                for num in range(len(self.query_test) + 1):  # 遍历每种增加的个数
                    for events in itertools.combinations((self.query_test), num):  # 遍历每种num数量下的event
                        temp_one_query = basic_query.head
                        query_temp = basic_query.body
                        if query_temp.find("==>") == -1 and num != 0:  # 机密性询问
                            query_temp += "==>"
                        for event in events:  # 遍历每个event，增加
                            if query_temp[-1] == ">":
                                query_temp += event
                            else:
                                query_temp += "||" + event
                        query_temp += ".\n"
                        temp_one_query += query_temp
                        self.all_queries.append(Query(self.scene_name, basic_query.name, temp_one_query, events))
        #self.all_queries.reverse()
    def get_scene_name(self):
        return self.scene_name
    def get_content(self):
        return self.all_queries, self.content

class Reg(Content):
    '''
    生成注册阶段.pv文件文本的类，需要其他类辅助生成
    '''
    def __init__(self):
        Content.__init__(self)
        self.content = ["let system(appid:Appid,aaid:AAID,skAT:sskey,uname:Uname,password:bitstring,facetid:Facetid,callerid:Callerid,personaid:PersonaID,token:bitstring,wrapkey:key)=\n" ,
                        "(\n" ,
                        "\tnew SR:channel; new https:channel; new CU:channel; new MC:channel; new AM:channel;\n" ,
                        "\tlet pkAT = spk(skAT) in\n",
                        "\tnew skAUbasic:sskey; new cntrbasic:CNTR; new kidbasic:KeyID;\n" ,
                        "\tnew fakefacetid:Facetid; new fakecallerid:Callerid; new fakepersonaid:PersonaID;\n" ,
                        "\t(* the attacker has access to following fields *)\n" ,
                        "\tout(c,(uname,appid,facetid,callerid,fakefacetid,personaid,fakepersonaid,aaid,pkAT));\n" ,
                        "\t(*insert AppList(appid,facetid);*)\n",
                        "\t(event leak_token();out(c,token))|\n",
                        "\t(event leak_kw(); out(c,wrapkey))|\n",
                        "\t(event leak_skat(); out(c,skAT))|\n",
                        "\t(event malicious_RP_to_US();Reg_malicious_RP_to_US(SR))|\n",
                        "\t(event malicious_US_to_RP();Reg_malicious_US_to_RP(SR))|\n",
                        "\t(event malicious_UA_to_RP(); Reg_malicious_UA_to_RP(https))|\n",
                        "\t(event malicious_UA_to_UC();Reg_malicious_UA_to_UC(CU))|\n",
                        "\t(event malicious_UC_to_UA();Reg_malicious_UC_to_UA(CU))|\n",
                        "\t(event malicious_UC_to_ASM();Reg_malicious_UC_to_ASM(MC))|\n",
                        "\t(event malicious_ASM_to_UC();Reg_malicious_ASM_to_UC(MC))|\n",
                        "\t(event malicious_ASM_to_Autr();Reg_malicious_ASM_to_Autr(AM))|\n",
                        "\t(event malicious_Autr_to_ASM();Reg_malicious_Autr_to_ASM(AM))|\n",
                        "\tRegUS_(SR, appid, facetid)|\n",
                        "\tRegRP_(SR, https, uname, password)|\n",
                        "\tRegUA_(https, CU,uname, password,facetid)|\n",
                        "\tRegUC_(CU, MC, callerid)|\n",
                        "\tRegASM_(MC, AM, token, callerid, personaid)|\n",
                        "\tRegAutr_(AM, aaid, skAT, wrapkey,skAUbasic,cntrbasic,kidbasic)\n" ,
                        ").\n" ,
                        "process\n" ,
                        "( \n" ,
                        "\tnew appid:Appid; new aaid:AAID; new callerid:Callerid;  new personaid:PersonaID; new skAT:sskey;  new wrapkey:key; new token:bitstring;\n" ,
                        "\tnew uname:Uname; new password:bitstring; let facetid = find_facetid(appid) in\n" ,
                        "\t(* User 1 registers in RP 1 *)\n" ,
                        "\tsystem(appid,aaid,skAT,uname,password,facetid,callerid,personaid,token,wrapkey)\n"
                        ")\n"]
        self.basic_queries = [
                            Basic_Query("s-skau","query seed:bitstring; ","attacker(gen_skAU(new skAUbasic,seed))"),
                            Basic_Query("s-cntr","query seed:bitstring;","attacker(gen_cntr(new cntrbasic,seed))"),
                            Basic_Query("s-skat", "query ","attacker(new skAT)"),
                            Basic_Query("Rauth", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; ","inj-event(RP_success_reg(u,a,aa,kid)) ==> (inj-event(Autr_verify_reg(u,a,aa,kid)) ==>inj-event(UA_init_reg(u)))")]
        self.query_test = ["event(leak_token)",
                           "event(leak_kw)",
                           "event(leak_skat)",
                           "event(malicious_US_to_RP)",
                           "event(malicious_RP_to_US)",
                           "event(malicious_UA_to_RP)",
                           "event(malicious_UA_to_UC)",
                           "event(malicious_UC_to_UA)",
                           "event(malicious_UC_to_ASM)",
                           "event(malicious_ASM_to_UC)",
                           "event(malicious_ASM_to_Autr)",
                           "event(malicious_Autr_to_ASM)"
                           ]
        self.all_queries = []
        self.scene_name = "has_not_set"
        self.if_set_type = False
        self.need_type_row = 21
        self.need_type_num = 6

class Reg_1b_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1b_seta"
        self.set_type("1b_seta")
        self.basic_queries.append(Basic_Query("s-ak","query ","attacker(To_12b_token(new appid,new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_1b_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1b_noa"
        self.set_type("1b_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(facetid_to_appid(new facetid),new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_2b_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2b_seta"
        self.set_type("2b_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(new appid,new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_2b_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2b_noa"
        self.set_type("2b_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(facetid_to_appid(new facetid),new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_1r_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1r_seta"
        self.set_type("1r_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(new appid))"))
        self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_1r_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1r_noa"
        self.set_type("1r_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(facetid_to_appid(new facetid)))"))
        self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_2r_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2r_seta"
        self.set_type("2r_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(new appid))"))
        self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(senc((gen_skAU(new skAUbasic,seed),ak),new wrapkey))"))
        self.get_group_queries()

class Reg_2r_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2r_noa"
        self.set_type("2r_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(facetid_to_appid(new facetid)))"))
        self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(senc((gen_skAU(new skAUbasic,seed),ak),new wrapkey))"))
        self.get_group_queries()

class Auth(Content):
    def __init__(self):
        Content.__init__(self)
        self.content = ["let system(appid:Appid,aaid:AAID,skAU:sskey,keyid:KeyID,wrapkey:key,token:bitstring,uname:Uname,facetid:Facetid,callerid:Callerid,personaid:PersonaID,cntr:CNTR) =\n",
                        "(\n",
                        "\tlet pkAU = spk(skAU) in \n",
                        "\tout(c,(uname,appid,facetid,aaid,callerid,personaid,pkAU)); (* public info *)\n",
                        "\t( \n",
                        "\t\tnew SR:channel; new https:channel; new CU:channel; new MC:channel; new AM:channel;\n",
                        "\t\tnew fakecallerid:Callerid; new fakefacetid:Facetid; new fakepersonaid:PersonaID;\n",
                        "\t\tnew tr:Tr;\n",
                        "\t\t(event leak_token(); out(c,token))|\n",
                        "\t\t(*(event leak_kw(); out(c,wrapkey))|*)\n",
                        "\t\t(*(event leak_skau(); out(c,skAU))|*)\n",
                        "\t\t(*(event leak_cntr(); out(c,cntr))|*)\n",
                        "\t\t(event leak_kid(); out(c,kid))|\n",
                        "\t\t(event malicious_RP_to_US(); !Auth_malicious_RP_to_US(SR))|\n",
                        "\t\t(event malicious_US_to_RP();  !Auth_malicious_US_to_RP(SR))|\n",
                        "\t\t(event malicious_UA_to_RP(); !Auth_malicious_UA_to_RP(https))|\n",
                        "\t\t(event malicious_UA_to_UC(); !Auth_malicious_UA_to_UC(CU))|\n",
                        "\t\t(event malicious_UC_to_UA();  !Auth_malicious_UC_to_UA(CU))|\n",
                        "\t\t(event malicious_UC_to_ASM();  !Auth_malicious_UC_to_ASM(MC))|\n",
                        "\t\t(event malicious_ASM_to_UC(); !Auth_malicious_ASM_to_UC(MC))|\n",
                        "\t\t(event malicious_ASM_to_Autr(); !Auth_malicious_ASM_to_Autr(AM))|\n",
                        "\t\t(event malicious_Autr_to_ASM(); !Auth_malicious_Autr_to_ASM(AM))|\n",
                        "\t\tAuthUS_(SR, uname, appid, aaid,kid,pkAU,cntr,tr)|\n",
                        "\t\tAuthRP_(SR, https)|\n",
                        "\t\tAuthRP_(SR, c)|\n",
                        "\t\tAuthUA_(https, CU,uname)|\n",
                        "\t\tAuthUC_(CU, MC, facetid)|\n",
                        "\t\tAuthASM_(MC,AM,token,callerid,callerid,personaid,appid,kid,kh)|\n",
                        "\t\tAuthAutr_(AM,aaid,wrapkey,cntr,tr,appid,kh)\n",
                        "\t)\n",
                        ").\n",
                        "process\n",
                        "(\n",
                        "\tnew appid:Appid; new aaid:AAID; new skAU:sskey;  new keyid:KeyID; new wrapkey:key;new token:bitstring; new uname:Uname; new cntr:CNTR;\n",
                        "\tlet facetid = find_facetid(appid) in\n",
                        "\tnew callerid:Callerid;\n",
                        "\tnew personaid:PersonaID;\n",
                        "\t(* User 1 authenticates in RP 1 *)\n",
                        "\tsystem(appid,aaid,skAU,keyid,wrapkey,token,uname,facetid,callerid,personaid,cntr)\n",
                        ")\n"]
        self.basic_queries = [Basic_Query("s-skau", "query ", "attacker(new skAU)"),
                              Basic_Query("s-cntr", "query ", "attacker(new cntr)")
                                ]
        self.query_test = ["event(malicious_US_to_RP)",
                           "event(malicious_RP_to_US)",
                           "event(malicious_UA_to_RP)",
                           "event(malicious_UA_to_UC)",
                           "event(malicious_UC_to_UA)",
                           "event(malicious_UC_to_ASM)",
                           "event(malicious_ASM_to_UC)",
                           "event(malicious_ASM_to_Autr)",
                           "event(malicious_Autr_to_ASM)",
                           "event(malicious_RP_to_UA)",
                           "event(leak_token)",
                           #"event(leak_kw)",
                           #"event(leak_skau)",
                           #"event(leak_cntr)",
                           "event(leak_kid)"
                           ]
        self.all_queries = []
        self.scene_name = "has_not_set"
        self.if_set_type = False
        self.need_specific_operation_row = 3
        self.need_type_row = 22
        self.need_type_num = 7

    def add_specific_operation(self):
        for i in range(len(self.specific_operation)):
            self.content.insert(self.need_specific_operation_row + i, self.specific_operation[i])
            self.need_type_row += 1
    def add_open_rp(self):
        self.content.insert(self.need_type_row - 3,
                            "\t\t(event malicious_RP_to_UA(); !Auth_malicious_RP_to_UA(https))|\n")
        self.need_type_row += 1

class Auth_1b_login_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_login_seta"
        self.specific_operation = ["\t\tlet ak = To_12b_token(appid,token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_open_rp()
        self.add_specific_operation()
        self.set_type("1b_login_seta")
        self.basic_queries.append(Basic_Query("s-ak", "query ", "attacker(To_12b_token(new appid,new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-kid","query ","attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br","query u:Uname,a:Appid,aa:AAID,kid:KeyID;","inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.get_group_queries()

class Auth_1b_login_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_login_noa"
        self.specific_operation = ["\t\tlet ak = To_12b_token(facetid_to_appid(facetid),token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid)),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_open_rp()
        self.add_specific_operation()
        self.set_type("1b_login_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(facetid_to_appid(new facetid),new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-kid", "query ", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br","query u:Uname,a:Appid,aa:AAID,kid:KeyID;","inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.get_group_queries()

class Auth_1b_stepup_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_stepup_seta"
        self.specific_operation = ["\t\tlet ak = To_12b_token(appid,token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("1b_login_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(new appid,new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-kid", "query seed:bitstring,ak:bitstring;", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br","query u:Uname,a:Appid,aa:AAID,kid:KeyID;","inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> UA_launch_auth_tr(tr))"))
        self.get_group_queries()

class Auth_1b_stepup_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_stepup_noa"
        self.specific_operation = ["\t\tlet ak = To_12b_token(facetid_to_appid(facetid),token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid)),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("1b_stepup_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(facetid_to_appid(new facetid),new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-kid", "query seed:bitstring,ak:bitstring;", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> UA_launch_auth_tr(tr))"))
        self.get_group_queries()

class Auth_2b_stepup_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2b_stepup_seta"
        self.specific_operation = ["\t\tlet ak = To_12b_token(appid,token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid),keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("2b_stepup_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(new appid,new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-kid", "query seed:bitstring,ak:bitstring;", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> UA_launch_auth_tr(tr))"))
        self.get_group_queries()

class Auth_2b_stepup_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2b_stepup_noa"
        self.specific_operation = ["\t\tlet ak = To_12b_token(facetid_to_appid(facetid),token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid)),keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("2b_stepup_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(facetid_to_appid(new facetid),new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-kid", "query seed:bitstring,ak:bitstring;", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> UA_launch_auth_tr(tr))"))
        self.get_group_queries()

class Auth_1r_login_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_login_seta"
        self.specific_operation = ["\t\tlet ak = To_12r_token(appid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_open_rp()
        self.add_specific_operation()
        self.set_type("1r_login_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(new appid))"))
        self.basic_queries.append(Basic_Query("s-kid", "query ", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.get_group_queries()

class Auth_1r_login_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_login_noa"
        self.specific_operation = ["\t\tlet ak = To_12r_token(facetid_to_appid(facetid)) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid)),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_open_rp()
        self.add_specific_operation()
        self.set_type("1r_login_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(facetid_to_appid(new facetid)))"))
        self.basic_queries.append(Basic_Query("s-kid", "query ", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.get_group_queries()


class Auth_1r_stepup_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_stepup_seta"
        self.specific_operation = ["\t\tlet ak = To_12r_token(appid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("1r_stepup_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(new appid))"))
        self.basic_queries.append(Basic_Query("s-kid", "query ", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> UA_launch_auth_tr(tr))"))
        self.get_group_queries()




class Auth_1r_stepup_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_stepup_noa"
        self.specific_operation = ["\t\tlet ak = To_12r_token(facetid_to_appid(facetid)) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid)),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("1r_stepup_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(facetid_to_appid(new facetid)))"))
        self.basic_queries.append(Basic_Query("s-kid", "query ", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> UA_launch_auth_tr(tr))"))
        self.get_group_queries()


class Auth_2r_stepup_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2r_stepup_seta"
        self.specific_operation = ["\t\tlet ak = To_12r_token(appid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid)),wrapkey) in\n",
                                   "\t\tlet kid = kh in\n",
                                   "\t\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("2r_stepup_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(new appid))"))
        self.basic_queries.append(Basic_Query("s-kid","query ak:bitstring;","attacker(senc((new skAU,ak),new wrapkey))"))
        self.basic_queries.append(Basic_Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> UA_launch_auth_tr(tr))"))
        self.get_group_queries()

class Auth_2r_stepup_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2r_stepup_noa"
        self.specific_operation = ["\t\tlet ak = To_12r_token(facetid_to_appid(facetid)) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid))),wrapkey) in\n",
                                   "\t\tlet kid = kh in\n",
                                   "\t\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("2r_stepup_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(facetid_to_appid(new facetid)))"))
        self.basic_queries.append(
            Basic_Query("s-kid", "query ak:bitstring;", "attacker(senc((new skAU,ak),new wrapkey))"))
        self.basic_queries.append(Basic_Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> UA_launch_auth_tr(tr))"))
        self.get_group_queries()
