from Definition import Query

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
        self.leak_fields = ["\t\tout(c,token);\n",
                            "\t\tout(c,wrapkey);\n",
                            "\t\tout(c,skAT);\n"]
        self.queries = [Query("s-skau","query secret testskAU.\n"),
                        Query("s-ak","query secret testak.\n"),
                        Query("s-cntr","query secret testcntr.\n"),
                        Query("s-kid","query secret testkid.\n"),
                        Query("S-skat", "query attacker(new skAT).\n"),
                        Query("Rauth","query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_reg(u,a,aa,kid)) ==> (inj-event(Autr_verify_reg(u,a,aa,kid))==> inj-event(UA_init_reg(u))).\n")]
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
        return []
    def get_open_rp(self):
        return []


class Reg_1b_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1b_seta"
        honest_name = ["\t\t!RegUS_seta","\t\t!RegRP_seta","\t\t!RegRP_seta","\t\t!RegUA_seta","\t\t!RegUC_seta","\t\t!RegASM_1b2b","\t\t!RegAutr_1b"]
        malicious_name = ["\t\t!RegUS_seta","\t\t!RegRP_seta","\t\t!RegUA_seta","\t\t!RegUC_seta","\t\t!RegUC_seta","\t\t!RegASM_1b2b","\t\t!RegASM_1b2b","\t\t!RegAutr_1b"]
        self.complete_content(honest_name,malicious_name)

class Reg_1b_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1b_noa"
        honest_name = ["\t\t!RegUS_noa","\t\t!RegRP_noa","\t\t!RegRP_noa","\t\t!RegUA_noa","\t\t!RegUC_noa","\t\t!RegASM_1b2b","\t\t!RegAutr_1b"]
        malicious_name = ["\t\t!RegUS_noa","\t\t!RegRP_noa","\t\t!RegUA_noa","\t\t!RegUC_noa","\t\t!RegUC_noa","\t\t!RegASM_1b2b","\t\t!RegASM_1b2b","\t\t!RegAutr_1b"]
        self.complete_content(honest_name,malicious_name)

class Reg_2b_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2b_seta"
        honest_name = ["\t\t!RegUS_seta","\t\t!RegRP_seta","\t\t!RegRP_seta","\t\t!RegUA_seta","\t\t!RegUC_seta","\t\t!RegASM_1b2b","\t\t!RegAutr_2b"]
        malicious_name = ["\t\t!RegUS_seta","\t\t!RegRP_seta","\t\t!RegUA_seta","\t\t!RegUC_seta","\t\t!RegUC_seta","\t\t!RegASM_1b2b","\t\t!RegASM_1b2b","\t\t!RegAutr_2b"]
        self.complete_content(honest_name,malicious_name)

class Reg_2b_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2b_noa"
        honest_name = ["\t\t!RegUS_noa","\t\t!RegRP_noa","\t\t!RegRP_noa","\t\t!RegUA_noa","\t\t!RegUC_noa","\t\t!RegASM_1b2b","\t\t!RegAutr_2b"]
        malicious_name = ["\t\t!RegUS_noa","\t\t!RegRP_noa","\t\t!RegUA_noa","\t\t!RegUC_noa","\t\t!RegUC_noa","\t\t!RegASM_1b2b","\t\t!RegASM_1b2b","\t\t!RegAutr_2b"]
        self.complete_content(honest_name,malicious_name)

class Reg_1r_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1r_seta"
        honest_name = ["\t\t!RegUS_seta","\t\t!RegRP_seta","\t\t!RegRP_seta","\t\t!RegUA_seta","\t\t!RegUC_seta","\t\t!RegASM_1r2r","\t\t!RegAutr_1r"]
        malicious_name = ["\t\t!RegUS_seta","\t\t!RegRP_seta","\t\t!RegUA_seta","\t\t!RegUC_seta","\t\t!RegUC_seta","\t\t!RegASM_1r2r","\t\t!RegASM_1r2r","\t\t!RegAutr_1r"]
        self.complete_content(honest_name,malicious_name)
class Reg_1r_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_1r_noa"
        honest_name = ["\t\t!RegUS_noa","\t\t!RegRP_noa","\t\t!RegRP_noa","\t\t!RegUA_noa","\t\t!RegUC_noa","\t\t!RegASM_1r2r","\t\t!RegAutr_1r"]
        malicious_name = ["\t\t!RegUS_noa","\t\t!RegRP_noa","\t\t!RegUA_noa","\t\t!RegUC_noa","\t\t!RegUC_noa","\t\t!RegASM_1r2r","\t\t!RegASM_1r2r","\t\t!RegAutr_1r"]
        self.complete_content(honest_name,malicious_name)
class Reg_2r_seta(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2r_seta"
        honest_name = ["\t\t!RegUS_seta","\t\t!RegRP_seta","\t\t!RegRP_seta","\t\t!RegUA_seta","\t\t!RegUC_seta","\t\t!RegASM_1r2r","\t\t!RegAutr_2r"]
        malicious_name = ["\t\t!RegUS_seta","\t\t!RegRP_seta","\t\t!RegUA_seta","\t\t!RegUC_seta","\t\t!RegUC_seta","\t\t!RegASM_1r2r","\t\t!RegASM_1r2r","\t\t!RegAutr_2r"]
        self.complete_content(honest_name,malicious_name)
class Reg_2r_noa(Reg):
    def __init__(self):
        Reg.__init__(self)
        self.scene_name = "Reg_2r_noa"
        honest_name = ["\t\t!RegUS_noa","\t\t!RegRP_noa","\t\t!RegRP_noa","\t\t!RegUA_noa","\t\t!RegUC_noa","\t\t!RegASM_1r2r","\t\t!RegAutr_2r"]
        malicious_name = ["\t\t!RegUS_noa","\t\t!RegRP_noa","\t\t!RegUA_seta","\t\t!RegUC_noa","\t\t!RegUC_noa","\t\t!RegASM_1r2r","\t\t!RegASM_1r2r","\t\t!RegAutr_2r"]
        self.complete_content(honest_name,malicious_name)
