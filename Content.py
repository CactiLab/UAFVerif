class Base_content:
    def __init__(self):
        self.if_add = -4
    def add_query(self, query, query_name):
        self.content.insert(0,query)
        self.if_add = self.if_add + 1
        self.query_name = query_name
    def add_honest_entities(self, honest_entities, scene_name):
        for line in honest_entities:
            self.content.insert(self.insert_number, line)
            self.insert_number += 1
        self.reset_insert_number()
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

class Reg_content(Base_content):
    '''
    生成注册阶段.pv文件文本的类，需要其他类辅助生成
    '''
    def __init__(self):
        Base_content.__init__(self)
        self.content = ["let system(appid:Appid,aaid:AAID,skAT:sskey,uname:Uname,password:bitstring,facetid:Facetid,callerid:Callerid,personaid:PersonaID,token:bitstring,wrapkey:key)=\n" ,
                        "(\n" ,
                        "   new SR:channel; new https:channel; new CU:channel; new MC:channel; new AM:channel;\n" ,
                        "   let pkAT = spk(skAT) in\n" ,
                        "   new fakefacetid:Facetid; new fakecallerid:Callerid; new fakepersonaid:PersonaID;\n" ,
                        "   (* the attacker has access to following fields *)\n" ,
                        "   out(c,(uname,appid,facetid,callerid,fakefacetid,personaid,fakepersonaid,aaid,pkAT));\n" ,
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
    def add_specific_operation(self, specific_operation):
        return
    def add_open_rp(self,open_rp):
        return
    def reset_insert_number(self):
        self.insert_number = 8

class Auth_content(Base_content):
    def __init__(self):
        Base_content.__init__(self)
        self.content = ["let system(appid:Appid,aaid:AAID,skAU:sskey,keyid:KeyID,wrapkey:key,token:bitstring,uname:Uname,facetid:Facetid,callerid:Callerid,personaid:PersonaID,cntr:CNTR) =\n",
                        "((* one RP authenticate one user many times *)\n",
                        "	let pkAU = spk(skAU) in let testskAU = skAU in\n",
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
                        "	!system(appid,aaid,skAU,keyid,wrapkey,token,uname,facetid,callerid,personaid,cntr)|\n",
                        "	(* User 2 authenticates in RP 1 *)\n",
                        "	!(\n",
                        "		new skAU2:sskey; new keyid2:KeyID; new wrapkey2:key; new token2:bitstring; new uname2:Uname; new cntr2:CNTR;\n",
                        "		system(appid,aaid,skAU2,keyid2,wrapkey2,token2,uname2,facetid,callerid,personaid,cntr2)\n",
                        "	)|\n",
                        "	(* User 1 authenticates in RP 2 *)\n",
                        "	!(\n",
                        "		new appid2:Appid; new skAU3:sskey; new keyid3:KeyID; new uname3:Uname; new cntr3:CNTR;\n",
                        "		system(appid2,aaid,skAU3,keyid3,wrapkey,token,uname3,facetid,callerid,personaid,cntr3)\n",
                        "	)\n",
                        ")\n"]
        self.insert_number = 12
        self.specific_operation_insert_number = 8
    def reset_insert_number(self):
        self.insert_number = 12
    def add_specific_operation(self, specific_operation):
        for line in specific_operation:
            self.content.insert(self.specific_operation_insert_number, line)
            self.specific_operation_insert_number += 1
    def add_open_rp(self,open_rp):
        for line in open_rp:
            self.content.insert(self.insert_number, line)
            self.insert_number += 1