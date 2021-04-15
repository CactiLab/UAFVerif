from Definition import Query

class Auth:
    def __init__(self):
        self.honest_entities = ["(SR, uname, appid, aaid,kid,pkAU,cntr,tr)|\n",
                                "(SR, https)|\n",
                                "(https, CU, uname)|\n",
                                "(CU, MC, facetid)|\n",
                                "(MC, AM, token, callerid, personaid)|\n",
                                "(AM, aaid, wrapkey, cntr, tr)\n"]
        self.malicious_entities = ["(c, uname, appid, aaid,kid,pkAU,cntr,tr)|\n",
                                   "(c, https)|\n",
                                   "(https, c, uname)|\n",
                                   "(c, MC, fakefacetid)|\n",
                                   "(CU, c, facetid)|\n",
                                   "(c, AM, token, fakecallerid, fakepersonaid)|\n",
                                   "(MC, c, token, callerid, personaid)|\n",
                                   "(c, aaid, wrapkey, cntr, tr)|\n"]
        self.leak_fields = ["\t\tout(c,token);\n",
                            "\t\tout(c,wrapkey);\n",
                            "\t\tout(c,skAU);\n",
                            "\t\tout(c,cntr);\n",
                            "\t\tout(c,kid);\n"]
        self.queries = [Query("s-ak", "query secret testak.\n"),
                        Query("s-cntr", "query secret testcntr.\n"),
                        Query("s-skau", "query secret testskAU.\n"),
                        Query("s-kid", "query secret kid.\n")]
        self.open_rp = []
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
    def get_specific_operation(self):
        return self.specific_operation
    def get_open_rp(self):
        return self.open_rp

class Auth_1b_seta_login(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_seta_login"
        self.queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        honest_name = ["\t\tAuthUS_seta_login", "\t\tAuthRP", "\t\tAuthUA_seta_login", "\t\tAuthUC_seta_login", "\t\tAuthASM_1b_login", "\t\tAuthAutr_1b_login"]
        malicious_name = ["\t\tAuthUS_seta_login", "\t\tAuthRP", "\t\tAuthUA_seta_login", "\t\tAuthUC_seta_login", "\t\tAuthUC_seta_login", "\t\tAuthASM_1b_login", "\t\tAuthASM_1b_login","\t\tAuthAutr_1b_login"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12b_token(appid,token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\tinsert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);\n"]
        self.open_rp.append("\t\tAuthRP(SR, c)|\n")

class Auth_1b_seta_stepup(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_seta_stepup"
        self.queries.append(Query("S-tr", "query secret testtr.\n"))
        self.queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        self.queries.append(Query("Aauth-tr",
                                  "query tr:Tr; inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr))).\n"))
        honest_name = ["\t\tAuthUS_seta_stepup", "\t\tAuthRP", "\t\tAuthUA_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthASM_1b_stepup", "\t\tAuthAutr_1b_stepup"]
        malicious_name = ["\t\tAuthUS_seta_stepup", "\t\tAuthRP", "\t\tAuthUA_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthASM_1b_stepup", "\t\tAuthASM_1b_stepup","\t\tAuthAutr_1b_stepup"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12b_token(appid,token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\tinsert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);\n"]


class Auth_1b_noa_login(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_noa_login"
        self.queries.append(Query("Aauth-1br",
                                  "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        honest_name = ["\t\tAuthUS_noa_login", "\t\tAuthRP", "\t\tAuthUA_noa_login", "\t\tAuthUC_noa_login",
                       "\t\tAuthASM_1b_login", "\t\tAuthAutr_1b_login"]
        malicious_name = ["\t\tAuthUS_noa_login", "\t\tAuthRP", "\t\tAuthUA_noa_login", "\t\tAuthUC_noa_login", "\t\tAuthUC_noa_login","\t\tAuthASM_1b_login", "\t\tAuthASM_1b_login", "\t\tAuthAutr_1b_login"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12b_token(facetid_to_appid(facetid),token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid)),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\tinsert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);\n"]
        self.open_rp.append("\t\tAuthRP(SR, c)|\n")

class Auth_1b_noa_stepup(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1b_noa_stepup"
        self.queries.append(Query("S-tr", "query secret testtr.\n"))
        self.queries.append(Query("Aauth-1br",
                                  "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        self.queries.append(Query("Aauth-tr",
                                  "query tr:Tr; inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr))).\n"))
        honest_name = ["\t\tAuthUS_noa_stepup", "\t\tAuthRP", "\t\tAuthUA_noa_stepup", "\t\tAuthUC_noa_stepup","\t\tAuthASM_1b_stepup", "\t\tAuthAutr_1b_stepup"]
        malicious_name = ["\t\tAuthUS_noa_stepup", "\t\tAuthRP", "\t\tAuthUA_noa_stepup", "\t\tAuthUC_noa_stepup", "\t\tAuthUC_noa_stepup","\t\tAuthASM_1b_stepup", "\t\tAuthASM_1b_stepup", "\t\tAuthAutr_1b_stepup"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12b_token(facetid_to_appid(facetid),token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid)),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\tinsert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);\n"]

class Auth_2b_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2b_seta"
        self.queries.append(Query("S-tr", "query secret testtr.\n"))
        self.queries.append(Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        self.queries.append(Query("Aauth-tr",
                                  "query tr:Tr; inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr))).\n"))
        honest_name = ["\t\tAuthUS_seta_stepup", "\t\tAuthRP", "\t\tAuthUA_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthASM_2b_stepup", "\t\tAuthAutr_2b_stepup"]
        malicious_name = ["\t\tAuthUS_seta_stepup", "\t\tAuthRP", "\t\tAuthUA_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthASM_2b_stepup", "\t\tAuthASM_2b_stepup","\t\tAuthAutr_2b_stepup"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12b_token(appid,token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid),keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\tinsert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);\n"]

class Auth_2b_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2b_noa"
        self.queries.append(Query("S-tr", "query secret testtr.\n"))
        self.queries.append(Query("Aauth-2br",
                                  "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        self.queries.append(Query("Aauth-tr",
                                  "query tr:Tr; inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr))).\n"))
        honest_name = ["\t\tAuthUS_noa_stepup", "\t\tAuthRP", "\t\tAuthUA_noa_stepup", "\t\tAuthUC_noa_stepup", "\t\tAuthASM_2b_stepup", "\t\tAuthAutr_2b_stepup"]
        malicious_name = ["\t\tAuthUS_noa_stepup", "\t\tAuthRP", "\t\tAuthUA_noa_stepup", "\t\tAuthUC_noa_stepup", "\t\tAuthUC_noa_stepup", "\t\tAuthASM_2b_stepup", "\t\tAuthASM_2b_stepup","\t\tAuthAutr_2b_stepup"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12b_token(facetid_to_appid(facetid),token,callerid,personaid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid)),keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\tinsert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);\n"]

class Auth_1r_seta_login(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_seta_login"
        self.queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        honest_name = ["\t\tAuthUS_seta_login", "\t\tAuthRP", "\t\tAuthUA_seta_login", "\t\tAuthUC_seta_login", "\t\tAuthASM_1r_login", "\t\tAuthAutr_1r_login"]
        malicious_name = ["\t\tAuthUS_seta_login", "\t\tAuthRP", "\t\tAuthUA_seta_login", "\t\tAuthUC_seta_login", "\t\tAuthUC_seta_login", "\t\tAuthASM_1r_login", "\t\tAuthASM_1r_login","\t\tAuthAutr_1r_login"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12r_token(appid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\tinsert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);\n"]
        self.open_rp.append("\t\tAuthRP(SR, c)|\n")

class Auth_1r_seta_stepup(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_seta_stepup"
        self.queries.append(Query("S-tr", "query secret testtr.\n"))
        self.queries.append(Query("Aauth-1br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        self.queries.append(Query("Aauth-tr",
                                  "query tr:Tr; inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr))).\n"))
        honest_name = ["\t\tAuthUS_seta_stepup", "\t\tAuthRP", "\t\tAuthUA_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthASM_1r_stepup", "\t\tAuthAutr_1r_stepup"]
        malicious_name = ["\t\tAuthUS_seta_stepup", "\t\tAuthRP", "\t\tAuthUA_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthASM_1r_stepup", "\t\tAuthASM_1r_stepup","\t\tAuthAutr_1r_stepup"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12r_token(appid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\tinsert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);\n"]


class Auth_1r_noa_login(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_noa_login"
        self.queries.append(Query("Aauth-1br",
                                  "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        honest_name = ["\t\tAuthUS_noa_login", "\t\tAuthRP", "\t\tAuthUA_noa_login", "\t\tAuthUC_noa_login", "\t\tAuthASM_1r_login", "\t\tAuthAutr_1r_login"]
        malicious_name = ["\t\tAuthUS_noa_login", "\t\tAuthRP", "\t\tAuthUA_noa_login", "\t\tAuthUC_noa_login", "\t\tAuthUC_noa_login", "\t\tAuthASM_1r_login", "\t\tAuthASM_1r_login","\t\tAuthAutr_1r_login"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12r_token(facetid_to_appid(facetid)) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid)),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\tinsert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);\n"]
        self.open_rp.append("\t\tAuthRP(SR, c)|\n")

class Auth_1r_noa_stepup(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_1r_noa_stepup"
        self.queries.append(Query("S-tr", "query secret testtr.\n"))
        self.queries.append(Query("Aauth-1br",
                                  "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_1br(u,a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        self.queries.append(Query("Aauth-tr",
                                  "query tr:Tr; inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr))).\n"))
        honest_name = ["\t\tAuthUS_noa_stepup", "\t\tAuthRP", "\t\tAuthUA_noa_stepup", "\t\tAuthUC_noa_stepup", "\t\tAuthASM_1r_stepup", "\t\tAuthAutr_1r_stepup"]
        malicious_name = ["\t\tAuthUS_noa_stepup", "\t\tAuthRP", "\t\tAuthUA_noa_stepup", "\t\tAuthUC_noa_stepup", "\t\tAuthUC_noa_stepup", "\t\tAuthASM_1r_stepup", "\t\tAuthASM_1r_stepup","\t\tAuthAutr_1r_stepup"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12r_token(facetid_to_appid(facetid)) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid)),uname,keyid),wrapkey) in\n",
                                   "\t\tlet kid = keyid in\n",
                                   "\t\tinsert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);\n"]

class Auth_2r_seta(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2r_seta"
        self.queries.append(Query("S-tr", "query secret testtr.\n"))
        self.queries.append(Query("Aauth-2br", "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        self.queries.append(Query("Aauth-tr","query tr:Tr; inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr))).\n"))
        honest_name = ["\t\tAuthUS_seta_stepup", "\t\tAuthRP", "\t\tAuthUA_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthASM_2r_stepup", "\t\tAuthAutr_2r_stepup"]
        malicious_name = ["\t\tAuthUS_seta_stepup", "\t\tAuthRP", "\t\tAuthUA_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthUC_seta_stepup", "\t\tAuthASM_2r_stepup", "\t\tAuthASM_2r_stepup","\t\tAuthAutr_2r_stepup"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12r_token(appid) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,appid)),wrapkey) in\n",
                                   "\t\tlet kid = kh in\n",
                                   "\t\tinsert ASMDB(appid,kid,kh); insert AutrDB(appid,kid,kh);\n"]

class Auth_2r_noa(Auth):
    def __init__(self):
        Auth.__init__(self)
        self.scene_name = "Auth_2r_noa"
        self.queries.append(Query("S-tr", "query secret testtr.\n"))
        self.queries.append(Query("Aauth-2br",
                                  "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> (inj-event(Autr_verify_auth_2br(a,aa,kid)) ==> inj-event(UA_launch_auth(u))).\n"))
        self.queries.append(Query("Aauth-tr", "query tr:Tr; inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr))).\n"))
        honest_name = ["\t\tAuthUS_noa_stepup", "\t\tAuthRP", "\t\tAuthUA_noa_stepup", "\t\tAuthUC_noa_stepup", "\t\tAuthASM_2r_stepup", "\t\tAuthAutr_2r_stepup"]
        malicious_name = ["\t\tAuthUS_noa_stepup", "\t\tAuthRP", "\t\tAuthUA_noa_stepup", "\t\tAuthUC_noa_stepup", "\t\tAuthUC_noa_stepup", "\t\tAuthASM_2r_stepup", "\t\tAuthASM_2r_stepup","\t\tAuthAutr_2r_stepup"]
        self.complete_content(honest_name, malicious_name)
        self.specific_operation = ["\t\tlet ak = To_12r_token(facetid_to_appid(facetid)) in\n",
                                   "\t\tlet kh = senc((skAU,f1(ak,facetid_to_appid(facetid))),wrapkey) in\n",
                                   "\t\tlet kid = kh in\n",
                                   "\t\tinsert ASMDB(facetid_to_appid(facetid),kid,kh); insert AutrDB(facetid_to_appid(facetid),kid,kh);\n"]