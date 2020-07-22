import itertools
import os
import time
import shutil
import random
from threading import Timer
from subprocess import Popen, PIPE
from multiprocessing import Process

class REG:
	__init__():
		#all registration authenticator types
		self.types = ["1b_autr","2b_autr","1r_autr","2r_autr"]
		# registration querys
		self.queries = dict()
		self.queries['RS-ak'] = "query secret testak."
		self.queries['RS-cntr'] = "query secret cntr."
		self.queries['RS-skau'] = "query secret skAU."
		self.queries['auth'] = "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_reg(u,a,aa,kid)) ==> (inj-event(Autr_verify_reg(u,a,aa,kid))==> inj-event(UA_init_reg(u,a)))."
		self.comp_fields = ["out(c,skAT);","out(c,token);","out(c,wrapkey);"]
		self.mali_entities=  []
		self.mali_entities.append("RegUA(https, c, uname,appid,password)|")
		self.mali_entities.append("RegUC(c, MC, fakefacetid)|")
		self.mali_entities.append("RegUC(CU, c, facetid)|")
		self.mali_entities.append("RegASM(c, AM, token, fakecallerid, atype)|")
		self.mali_entities.append("RegASM(MC, c, token, callerid, atype)|")
		self.mali_entities.append("RegAutr(c, aaid, skAT, wrapkey, atype)")
		self.reg_insert_line = 24 #insert line number
	def get_all_types():
		return self.types
	def get_all_comp_fields():
		comps = []
		for num in range(self.comp_fields.len()):
			for pre in iitertools.combinations(self.comp_fields, num):
				temp = []
				for item in pre:
					temp.append(item)
				comps.append(temp)
		return comps
	def get_all_entities():
		entities = []
		for num in range(self.mali_entities.len())
			temp = []
			for i in range(num):
				temp.append(self.mali_entities[i])
			entities.append(temp)
		return entities
	def get_all_queries():
		return self.queries

class AUTH:
	__init__():
		self.types = ["1b_autr","2b_autr","1r_autr","2r_autr"]
		self.querys = dict()
		
		
auth_query_1br = "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> inj-event(Autr_verify_auth_1br(u,a,aa,kid))."
auth_query_2br = "query u:Uname,a:Appid,aa:AAID,kid:KeyID; inj-event(RP_success_auth(u,a,aa,kid)) ==> inj-event(Autr_verify_auth_2br(a,aa,kid))."
auth_querys_tr = "query tr:Tr; inj-event(RP_success_tr(tr).) ==> inj-event(Autr_verify_tr(tr))"

auth_querys_1br = dict()
auth_querys_1br['AS-ak'] = 'query secret ak.'
auth_querys_1br['AS-cntr'] = 'query attacker(new cntr).'
auth_querys_1br['AS-skAU'] = 'query attacker(new SAuthenticationKey).'
auth_querys_1br['AS-tr'] = 'query attacker(new tr).'
auth_querys_1br['auth-base'] = (auth_query_1br)
auth_querys_1br['auth-tr'] = (auth_querys_tr)


auth_querys_2br = dict()
auth_querys_2br['AS-ak'] = 'query secret ak.'
auth_querys_2br['AS-cntr'] = 'query attacker(new cntr).'
auth_querys_2br['AS-skAU'] = 'query attacker(new SAuthenticationKey).'
auth_querys_2br['AS-tr'] = 'query attacker(new tr).'
auth_querys_2br['auth-base'] = (auth_query_2br)
auth_querys_2br['auth-tr'] = (auth_querys_tr)

typesAA = []
typesAA.append('A_1b_empty')
typesAA.append('A_1b_setup')
typesAA.append('A_1r_empty')
typesAA.append('A_1r_setup')
typesAA.append('A_2b')
typesAA.append('A_2r')



def make_temp_file():
	for type in typesRA:
		dir = "FIDO\\results\\" + type
		if os.path.exists(dir):
			shutil.rmtree(dir,True)
			os.makedirs(dir)
		else:
			os.makedirs(dir)
	for type in typesAA:
		dir = "FIDO\\results\\" + type
		if os.path.exists(dir):
			shutil.rmtree(dir,True)
			os.makedirs(dir)
		else:
			os.makedirs(dir)
	f1 = open('FIDO\FIDO.pvl','r')
	f2 = open('FIDO\\templib.pvl','w')
	all = f1.readlines()
	f2.writelines(all)
	f1.close()
	f2.close()

"""
"""
def analysis_reg(types,):
	make_temp_file();
	log = open('recode.log', mode = 'a',encoding='utf-8')
	REG reg
	for type in types: #all types of the authenticators
		for usenum in range(reg_out_lines.len()):
			for pre in iitertools.combinations(reg_out_lines, usenum): #for any  combinations
				
				
		for q in reg_queries:
			



	

	
analysis();