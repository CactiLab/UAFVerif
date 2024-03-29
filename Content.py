import copy
import os
import itertools
from Definition import Basic_Query,Query

class Content:
    '''
    set the template content and generate the queries of each case
    '''
    # statrt from the 'need_type_row', add the type of this case for 'need_type_num' lines
    def set_type(self,type):
        for i in range(self.need_type_num):  # add the type of this case, eg: RegUS_ to RegUS_1b_seta
            index = self.content[self.need_type_row + i].rindex("_") + 1  # insert the type string after the last '_'
            list_str = list(self.content[self.need_type_row + i])
            list_str.insert(index, type)
            self.content[self.need_type_row + i] = "".join(list_str)
        self.if_set_type = True
    def get_group_queries(self):
        for basic_query in self.basic_queries:  # iterate over all basic query statements
            if basic_query.name.find("auth") == -1:  # if secrecy properties
                # Basic_Query("s-skau","query seed:bitstring; ","attacker(gen_skAU(new skAUbasic,seed))"),
                #               name            head                            body
                temp_group_query = basic_query.head + "\n"
                for num in range(len(self.query_test) + 1):  # get all combinaions of attacker abilities
                    for events in itertools.combinations((self.query_test), num):  # get the combinations with 'num' attacker abilities
                        query_temp = basic_query.body        # construct the body of the queries
                        if query_temp.find("==>") == -1 and num != 0:  # if secrecy properties + with constrains on attacker abilities
                            query_temp += "==>"              # query_temp = body==>
                        for event in events:                 # for each attacker ability in a specific combination, 
                            if query_temp[-1] == ">":        # add the first ability
                                query_temp += event          # query_temp = body==>event1
                            else:                            # add subsequent abilities
                                query_temp += "||" + event   # query_temp = body==>event_1||event_2...
                        query_temp += ";\n"                  # the end of query, query_temp = body==>event_1||event_2...||event_n;\n
                        temp_group_query += query_temp       # temp_group_query = head\n body==>event_1||event_2...||event_n;\n
                index = temp_group_query.rindex(";")
                list_str = list(temp_group_query)
                list_str[index] = "."  # set the last ';' to '.'
                temp_group_query = "".join(list_str) 
                # for each secrecy query, add an element in secrecy_queries
                # the element is of the form head\n body==>event_11||event_12...||event_1n;...event_n1||event_n2...||event_nn.
                # Query(scene_name, query_name, content, assumptions)
                self.secrecy_queries.append(Query(self.scene_name,basic_query.name,temp_group_query,[]))
            else:  # authentication properties
                for num in range(len(self.query_test) + 1):  # get all combinaions of attacker abilities
                    for events in itertools.combinations((self.query_test), num):  # get the combinations with 'num' attacker abilities
                        temp_one_query = basic_query.head + basic_query.body + ".\n"
                        # for each event conbination, add an element in auth_queries
                        # Query(scene_name, query_name, content, assumptions)
                        self.auth_queries.append(Query(self.scene_name, basic_query.name, temp_one_query, events))

    def get_scene_name(self):
        return self.scene_name
    def get_content(self):
        return self.secrecy_queries, self.auth_queries, self.content

class Reg(Content):
    '''
    the class to generate .pv files in authenticator registration
    '''
    def __init__(self):
        Content.__init__(self)
        self.content = ["let system(appid:Appid,aaid:AAID,skAT:sskey,uname:Uname,password:bitstring,facetid:Facetid,callerid:Callerid,personaid:PersonaID,token:bitstring,wrapkey:key)=\n" ,
                        "(\n" ,
                        "\t(*new SR:channel; new https:channel; new CU:channel; new MC:channel; new AM:channel;*)\n" ,
                        "\tlet pkAT = spk(skAT) in\n",
                        "\tnew skAUbasic:sskey; new cntrbasic:CNTR; new kidbasic:KeyID;\n" ,
                        "\tnew fakefacetid:Facetid; new fakecallerid:Callerid; new fakepersonaid:PersonaID;\n" ,
                        "\t(* the attacker has access to following fields *)\n" ,
                        "\tout(c,(uname,appid,facetid,callerid,fakefacetid,personaid,fakepersonaid,aaid,skAT,pkAT));\n" ,
                        "\t(*insert AppList(appid,facetid);*)\n",
                        "\t(event leak_token();out(c,token))|\n", # attacker abilities
                        "\t(event leak_kw(); out(c,wrapkey))|\n",
                        "\t(event malicious_RP_to_US();RegUS_(c, appid, facetid))|\n", # set type started-------row number = 12
                        "\t(event malicious_US_to_RP();RegRP_(c, https, uname, password))|\n",
                        "\t(event malicious_UA_to_RP(); RegRP_(SR, c, uname, password))|\n",
                        "\t(event malicious_UA_to_UC();RegUC_(c,MC,fakefacetid))|\n",
                        "\t(event malicious_UC_to_UA();RegUA_(https, c, uname, password))|\n",
                        "\t(event malicious_UC_to_ASM();RegASM_(c,AM,token, fakecallerid, personaid))|\n",
                        "\t(event malicious_ASM_to_UC();RegUC_(CU,c,facetid))|\n",
                        "\t(event malicious_ASM_to_Autr();RegAutr_(c,aaid, skAT, wrapkey,skAUbasic,cntrbasic,kidbasic))|\n",
                        "\t(event malicious_Autr_to_ASM();RegASM_(MC,c,token, callerid, personaid))|\n",
                        "\tRegUS_(SR, appid, facetid)|\n", # normal process started
                        "\tRegRP_(SR, https, uname, password)|\n",
                        "\tRegUA_(https, CU, uname, password)|\n",
                        "\tRegUC_(CU,MC,facetid)|\n",
                        "\tRegASM_(MC,AM,token, callerid, personaid)|\n",
                        "\tRegAutr_(AM,aaid, skAT, wrapkey,skAUbasic,cntrbasic,kidbasic)\n", # set type ended-------total num = 14
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
                            Basic_Query("Rauth", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; ","inj-event(RP_success_reg(u,a,aa,kid)) ==> (inj-event(Autr_verify_reg(u,a,aa,kid)) ==>inj-event(UA_init_reg(u)))")
                            ]
        # all possible attacker abilities
        self.query_test = ["event(leak_token)",
                           "event(leak_kw)",
                           #"event(leak_skat)",
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

        self.secrecy_queries = []
        self.auth_queries = []
        self.scene_name = "has_not_set"
        self.if_set_type = False
        self.need_type_row = 11  # the start 
        self.need_type_num = 15  # the number of lines to set type

class Reg_1b_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1b_seta"
        self.set_type("1b_seta")
        self.basic_queries.append(Basic_Query("s-ak","query ","attacker(To_12b_token(new appid,new token,new callerid,new personaid))"))
        #self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries() # initiate self.secrecy_queries and self.auth_queries

class Reg_1b_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1b_noa"
        self.set_type("1b_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(facetid_to_appid(find_facetid(new appid)),new token,new callerid,new personaid))"))
        #self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_2b_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2b_seta"
        self.set_type("2b_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(new appid,new token,new callerid,new personaid))"))
        #self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_2b_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2b_noa"
        self.set_type("2b_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(facetid_to_appid(find_facetid(new appid)),new token,new callerid,new personaid))"))
        #self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_1r_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1r_seta"
        self.set_type("1r_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(new appid))"))
        #self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_1r_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1r_noa"
        self.set_type("1r_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(facetid_to_appid(find_facetid(new appid))))"))
        #self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(gen_kid(new kidbasic,seed))"))
        self.get_group_queries()

class Reg_2r_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2r_seta"
        self.set_type("2r_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(new appid))"))
        #self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(senc((gen_skAU(new skAUbasic,seed),ak),new wrapkey))"))
        self.get_group_queries()

class Reg_2r_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2r_noa"
        self.set_type("2r_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(facetid_to_appid(find_facetid(new appid))))"))
        #self.basic_queries.append(Basic_Query("s-kid","query seed:bitstring,ak:bitstring;","attacker(senc((gen_skAU(new skAUbasic,seed),ak),new wrapkey))"))
        self.get_group_queries()

class Auth(Content):
    def __init__(self):
        Content.__init__(self)
        self.content = ["let system(appid:Appid,aaid:AAID,skAU:sskey,keyid:KeyID,wrapkey:key,token:bitstring,uname:Uname,facetid:Facetid,callerid:Callerid,personaid:PersonaID) =\n",
                        "(\n",
                        "\tlet pkAU = spk(skAU) in \n",
                        "\tout(c,(uname,appid,facetid,aaid,callerid,personaid,pkAU,kid)); (* public info *)\n",
                        "\t( \n",
                        "\t(*new SR:channel; new https:channel; new CU:channel; new MC:channel; new AM:channel;*)\n",
                        "\tnew fakecallerid:Callerid; new fakefacetid:Facetid; new fakepersonaid:PersonaID;\n",
                        "\tnew cntr:CNTR; new tr:Tr; out(c,cntr);\n",
                        "\t(event leak_token(); out(c,token))|\n",
                        "\t(event leak_kw(); out(c,wrapkey))|\n",
                        "\t(event leak_skau(); out(c,skAU))|\n",
                        "\t(event leak_cntr(); out(c,cntr))|\n",
                        "\t(event malicious_US_to_RP();  AuthRP_(c, https))|\n",
                        "\t(*(event malicious_RP_to_US(); AuthUS_(c, uname, appid, aaid,kid,pkAU,cntr,tr))|*)\n",
                        "\t(event malicious_UA_to_RP(); AuthRP_(SR, c))|\n",
                        "\t(event malicious_UA_to_UC(); AuthUC_(c, MC, fakefacetid))|\n",
                        "\t(event malicious_UC_to_UA();  AuthUA_(https, c,uname))|\n",
                        "\t(event malicious_UC_to_ASM();  AuthASM_(c,AM,token,fakecallerid,callerid,personaid,appid,kid,kh))|\n",
                        "\t(event malicious_ASM_to_UC(); AuthUC_(CU, c, facetid))|\n",
                        "\t(event malicious_ASM_to_Autr(); AuthAutr_(c,aaid,wrapkey,cntr,tr,appid,kh))|\n",
                        "\t(*(event malicious_Autr_to_ASM(); AuthASM_(MC,c,token,callerid,callerid,personaid,appid,kid,kh))|*)\n",
                        "\tAuthUS_(SR, uname, appid, aaid,kid,pkAU,cntr,tr)|\n",
                        "\tAuthRP_(SR, https)|\n",
                        "\tAuthUA_(https, CU,uname)|\n",
                        "\tAuthUC_(CU, MC, facetid)|\n",
                        "\tAuthASM_(MC,AM,token,callerid,callerid,personaid,appid,kid,kh)|\n",
                        "\tAuthAutr_(AM,aaid,wrapkey,cntr,tr,appid,kh)\n",
                        "\t)\n",
                        ").\n",
                        "process\n",
                        "(\n",
                        "\tnew appid:Appid; new aaid:AAID; new skAU:sskey; new keyid:KeyID; new wrapkey:key; new token:bitstring; new uname:Uname;\n",
                        "\tlet facetid = find_facetid(appid) in\n",
                        "\tnew callerid:Callerid;\n",
                        "\tnew personaid:PersonaID;\n",
                        "\t(* User 1 authenticates in RP 1 *)\n",
                        "\t!system(appid,aaid,skAU,keyid,wrapkey,token,uname,facetid,callerid,personaid)\n",
                        ")\n"]
        self.basic_queries = [Basic_Query("s-skau", "query ", "attacker(new skAU)"),
                              Basic_Query("s-cntr", "query ", "attacker(new cntr)")
                                ]
        self.secrecy_queries = []
        self.auth_queries = []
        self.scene_name = "has_not_set"
        self.if_set_type = False
        self.need_specific_operation_row = 3
        self.need_type_row = 12
        self.need_type_num = 15
        self.event_line = 8
        self.query_test = ["event(leak_token)",
                           "event(leak_kw)",
                           "event(leak_skau)",
                           "event(leak_cntr)",
                           #"event(leak_kid)",
                           "event(malicious_US_to_RP)",
                           "event(malicious_RP_to_US)",
                           #"event(malicious_RP_to_UA)",
                           "event(malicious_UA_to_RP)",
                           "event(malicious_UA_to_UC)",
                           "event(malicious_UC_to_UA)",
                           "event(malicious_UC_to_ASM)",
                           "event(malicious_ASM_to_UC)",
                           "event(malicious_ASM_to_Autr)",
                           "event(malicious_Autr_to_ASM)",
                           ]
        self.query_delline = dict()

    def add_specific_operation(self):
        for i in range(len(self.specific_operation)):
            self.content.insert(self.need_specific_operation_row + i, self.specific_operation[i])
            self.need_type_row += 1
    def add_open_rp(self):
        self.content.insert(self.need_type_row + 1,
                            "\t(event malicious_RP_to_UA(); AuthUA_(c,CU,uname))|\n")
        self.content.insert(self.need_type_row + 2, "\t(event malicious_UA_to_RP(); AuthRP_(SR,c))|\n")
        self.query_test.append("event(malicious_RP_to_UA)")
        self.need_type_num += 2

class Auth_1b_login_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_login_seta"
        self.specific_operation = ["\tlet ak = To_12b_token(appid,token,callerid,personaid) in\n",
                                   "\tlet kh = senc((skAU,ak,uname,keyid),wrapkey) in\n",
                                   "\tlet kid = keyid in\n",
                                   "\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_open_rp()
        self.add_specific_operation()
        self.set_type("1b_login_seta")
        self.basic_queries.append(Basic_Query("s-ak", "query ", "attacker(To_12b_token(new appid,new token,new callerid,new personaid))"))
        #self.basic_queries.append(Basic_Query("s-kid","query ","attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br","query u:Uname,a:Appid,aa:AAID,kid:KeyID;","inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.get_group_queries()

class Auth_1b_login_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_login_noa"
        self.specific_operation = ["\tlet ak = To_12b_token(facetid_to_appid(facetid),token,callerid,personaid) in\n",
                                   "\tlet kh = senc((skAU,ak,uname,keyid),wrapkey) in\n",
                                   "\tlet kid = keyid in\n",
                                   "\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_open_rp()
        self.add_specific_operation()
        self.set_type("1b_login_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(facetid_to_appid(find_facetid(new appid)),new token,new callerid,new personaid))"))
        #self.basic_queries.append(Basic_Query("s-kid", "query ", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br","query u:Uname,a:Appid,aa:AAID,kid:KeyID;","inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.get_group_queries()

class Auth_1b_stepup_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_stepup_seta"
        self.specific_operation = ["\tlet ak = To_12b_token(appid,token,callerid,personaid) in\n",
                                   "\tlet kh = senc((skAU,ak,uname,keyid),wrapkey) in\n",
                                   "\tlet kid = keyid in\n",
                                   "\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("1b_stepup_seta")
        self.basic_queries.append(Basic_Query("s-ak", "query ", "attacker(To_12b_token(new appid,new token,new callerid,new personaid))"))
        #self.basic_queries.append(Basic_Query("s-kid", "query seed:bitstring,ak:bitstring;", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("s-tr", "query ", "attacker(new tr)"))
        self.basic_queries.append(Basic_Query("Aauth-1br","query u:Uname,a:Appid,aa:AAID,kid:KeyID;","inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr)))"))
        self.get_group_queries()

class Auth_1b_stepup_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_stepup_noa"
        self.specific_operation = ["\tlet ak = To_12b_token(facetid_to_appid(facetid),token,callerid,personaid) in\n",
                                   "\tlet kh = senc((skAU,ak,uname,keyid),wrapkey) in\n",
                                   "\tlet kid = keyid in\n",
                                   "\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("1b_stepup_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(facetid_to_appid(find_facetid(new appid)),new token,new callerid,new personaid))"))
        #self.basic_queries.append(Basic_Query("s-kid", "query seed:bitstring,ak:bitstring;", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("s-tr", "query ", "attacker(new tr)"))
        self.basic_queries.append(Basic_Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr)))"))
        self.get_group_queries()

class Auth_2b_stepup_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2b_stepup_seta"
        self.specific_operation = ["\tlet ak = To_12b_token(appid,token,callerid,personaid) in\n",
                                   "\tlet kh = senc((skAU,ak,keyid),wrapkey) in\n",
                                   "\tlet kid = keyid in\n",
                                   "\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("2b_stepup_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(new appid,new token,new callerid,new personaid))"))
        self.basic_queries.append(Basic_Query("s-tr", "query ", "attacker(new tr)"))
        #self.basic_queries.append(Basic_Query("s-kid", "query seed:bitstring,ak:bitstring;", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr)))"))
        self.get_group_queries()

class Auth_2b_stepup_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2b_stepup_noa"
        self.specific_operation = ["\tlet ak = To_12b_token(facetid_to_appid(facetid),token,callerid,personaid) in\n",
                                   "\tlet kh = senc((skAU,ak,keyid),wrapkey) in\n",
                                   "\tlet kid = keyid in\n",
                                   "\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("2b_stepup_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12b_token(facetid_to_appid(find_facetid(new appid)),new token,new callerid,new personaid))"))

        #self.basic_queries.append(Basic_Query("s-kid", "query seed:bitstring,ak:bitstring;", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("s-tr", "query ", "attacker(new tr)"))
        self.basic_queries.append(Basic_Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr)))"))
        self.get_group_queries()

class Auth_1r_login_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_login_seta"
        self.specific_operation = ["\tlet ak = To_12r_token(appid) in\n",
                                   "\tlet kh = senc((skAU,ak,uname,keyid),wrapkey) in\n",
                                   "\tlet kid = keyid in\n",
                                   "\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_open_rp()
        self.add_specific_operation()
        self.set_type("1r_login_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(new appid))"))
        #self.basic_queries.append(Basic_Query("s-kid", "query ", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.get_group_queries()

class Auth_1r_login_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_login_noa"
        self.specific_operation = ["\tlet ak = To_12r_token(facetid_to_appid(facetid)) in\n",
                                   "\tlet kh = senc((skAU,ak,uname,keyid),wrapkey) in\n",
                                   "\tlet kid = keyid in\n",
                                   "\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_open_rp()
        self.add_specific_operation()
        self.set_type("1r_login_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(facetid_to_appid(find_facetid(new appid))))"))
        #self.basic_queries.append(Basic_Query("s-kid", "query ", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.get_group_queries()


class Auth_1r_stepup_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_stepup_seta"
        self.specific_operation = ["\tlet ak = To_12r_token(appid) in\n",
                                   "\tlet kh = senc((skAU,ak,uname,keyid),wrapkey) in\n",
                                   "\tlet kid = keyid in\n",
                                   "\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("1r_stepup_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(new appid))"))
        #self.basic_queries.append(Basic_Query("s-kid", "query ", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("s-tr", "query ", "attacker(new tr)"))
        self.basic_queries.append(Basic_Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr)))"))
        self.get_group_queries()




class Auth_1r_stepup_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_stepup_noa"
        self.specific_operation = ["\tlet ak = To_12r_token(facetid_to_appid(facetid)) in\n",
                                   "\tlet kh = senc((skAU,ak,uname,keyid),wrapkey) in\n",
                                   "\tlet kid = keyid in\n",
                                   "\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("1r_stepup_noa")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(facetid_to_appid(find_facetid(new appid))))"))
        #self.basic_queries.append(Basic_Query("s-kid", "query ", "attacker(new keyid)"))
        self.basic_queries.append(Basic_Query("s-tr", "query ", "attacker(new tr)"))
        self.basic_queries.append(Basic_Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr)))"))
        self.get_group_queries()


class Auth_2r_stepup_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2r_stepup_seta"
        self.specific_operation = ["\tlet ak = To_12r_token(appid) in\n",
                                   "\tlet kh = senc((skAU,ak),wrapkey) in\n",
                                   "\tlet kid = kh in\n",
                                   "\t(*insert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("2r_stepup_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(new appid))"))
        #self.basic_queries.append(Basic_Query("s-kid","query ak:bitstring;","attacker(senc((new skAU,ak),new wrapkey))"))
        self.basic_queries.append(Basic_Query("s-tr", "query ", "attacker(new tr)"))
        self.basic_queries.append(Basic_Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr)))"))
        self.get_group_queries()

class Auth_2r_stepup_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2r_stepup_noa"
        self.specific_operation = ["\tlet ak = To_12r_token(facetid_to_appid(facetid)) in\n",
                                   "\tlet kh = senc((skAU,ak),wrapkey) in\n",
                                   "\tlet kid = kh in\n",
                                   "\t(*insert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);*)\n"]
        self.add_specific_operation()
        self.set_type("2r_stepup_seta")
        self.basic_queries.append(
            Basic_Query("s-ak", "query ", "attacker(To_12r_token(facetid_to_appid(find_facetid(new appid))))"))
        #self.basic_queries.append(Basic_Query("s-kid", "query ak:bitstring;", "attacker(senc((new skAU,ak),new wrapkey))"))
        self.basic_queries.append(Basic_Query("s-tr", "query ", "attacker(new tr)"))
        self.basic_queries.append(Basic_Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID;",
                                              "inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(aa,kid)) ==> inj-event(UA_launch_auth(u)))"))
        self.basic_queries.append(Basic_Query("Aauth-tr", "query tr:Tr;",
                                              "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr)))"))
        self.get_group_queries()
