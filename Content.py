import copy
from Definition import Query

class Reg():
    '''
    生成注册阶段.pv文件文本的类，需要其他类辅助生成
    '''
    def __init__(self):
        self.content = ["let system(appid:Appid,aaid:AAID,skAT:sskey,uname:Uname,password:bitstring,facetid:Facetid,callerid:Callerid,personaid:PersonaID,token:bitstring,wrapkey:key)=\n" ,
                        "(\n" ,
                        "\tnew SR:channel; new https:channel; new CU:channel; new MC:channel; new AM:channel;\n" ,
                        "\tlet pkAT = spk(skAT) in\n" ,
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
                        "\t(event malicious_ASM_to_Autr();!RegAutr_(c, aaid, skAT, wrapkey))|\n",
                        "\t(event malicious_Autr_to_ASM();!RegASM_(MC, c, token, callerid, personaid))|\n",
                        "\tRegUS_(SR, appid)|\n",
                        "\tRegRP_(SR, https, uname, password)|\n",
                        "\tRegUA_(https, CU,uname, password)|\n",
                        "\tRegUC_(CU, MC, facetid)|\n",
                        "\tRegASM_(MC, AM, token, callerid, personaid)|\n",
                        "\tRegAutr_(AM, aaid, skAT, wrapkey)\n" ,
                        ").\n" ,
                        "process\n" ,
                        "( \n" ,
                        "\tnew appid:Appid; new aaid:AAID; new facetid:Facetid;  new callerid:Callerid;  new personaid:PersonaID; new skAT:sskey;  new wrapkey:key; new token:bitstring;\n" ,
                        "\tnew uname:Uname; new password:bitstring;\n" ,
                        "\t(* User 1 registers in RP 1 *)\n" ,
                        "\tsystem(appid,aaid,skAT,uname,password,facetid,callerid,personaid,token,wrapkey)|\n"
                        "\t(* User 2 registers in RP 1*)\n" ,
                        "\t(\n" ,
                        "\t\tnew uname2:Uname;\n" ,
                        "\t\tnew password2:bitstring;\n" ,
                        "\t\tnew token2:bitstring;\n" ,
                        "\t\tnew wrapkey2:key;\n" ,
                        "\t\tsystem(appid,aaid,skAT,uname2,password2,facetid,callerid,personaid,token2,wrapkey2)\n" ,
                        "\t)|\n" ,
                        "\t(* User 1 registers in RP 2, we assume the same user will not use same UName and pwd in different RPs*)\n" ,
                        "\t(\n" ,
                        "\t\tnew appid2:Appid;\n" ,
                        "\t\tnew uname3:Uname;\n" ,
                        "\t\tnew password3:bitstring;\n" ,
                        "\t\tsystem(appid2,aaid,skAT,uname3,password3,facetid,callerid,personaid,token,wrapkey)\n" ,
                        "\t)\n" ,
                        ")\n"]
        self.basic_queries = [Query("s-skau","query secret testskAU.\n"),
                            Query("s-ak","query secret testak.\n"),
                            Query("s-cntr","query secret testcntr.\n"),
                            Query("s-kid","query secret testkid.\n"),
                            Query("S-skat", "query attacker(new skAT).\n"),
                            Query("Rauth","query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_reg(u,a,aa,kid)) ==> (inj-event(Autr_verify_reg(u,a,aa,kid))==> inj-event(UA_init_reg(u))).\n")]

        self.need_type_row = 11
        self.need_type_num = 16
        self.reg_1b_seta = self.get_type("1b_seta")
        self.reg_1b_noa = self.get_type("1b_noa")
        self.reg_2b_seta = self.get_type("2b_seta")
        self.reg_2b_noa = self.get_type("2b_noa")
        self.reg_1r_seta = self.get_type("1r_seta")
        self.reg_1r_noa = self.get_type("1r_noa")
        self.reg_2r_seta = self.get_type("2r_seta")
        self.reg_2r_noa = self.get_type("2r_noa")

    def get_type(self,type):
        output = copy.deepcopy(self.content)
        for i in range(self.need_type_num):  # 每行的指定位置加入类型字段，如
            index = output[self.need_type_row + i].rindex("_") + 1
            list_str = list(output[self.need_type_row + i])
            list_str.insert(index, type)
            output[self.need_type_row + i] = "".join(list_str)
        return output
    def get_reg_1b_seta(self):
        return self.reg_1b_seta
    def get_reg_1b_noa(self):
        return self.reg_1b_noa
    def get_reg_2b_seta(self):
        return self.reg_2b_seta
    def get_reg_2b_noa(self):
        return self.reg_2b_noa
    def get_reg_1r_seta(self):
        return self.reg_1r_seta
    def get_reg_1r_noa(self):
        return self.reg_1r_noa
    def get_reg_2r_seta(self):
        return self.reg_2r_seta
    def get_reg_2r_noa(self):
        return self.reg_2r_noa


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