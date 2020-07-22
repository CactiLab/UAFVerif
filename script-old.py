import itertools
import os
import time
import shutil
import random
from threading import Timer
from subprocess import Popen, PIPE
from multiprocessing import Process

# macro define for channel assumptions, the numbers indicate the lines in the .pv scripts.
chRR = 40
chRU = 41
chUU = 42
chUR = 43
chUC = 44
chCC = 45
chCUf = 46
chCU = 47
chCM = 48
chMM = 49
chMCf = 50
chMC = 51
chMA = 52
chAA = 53
chAM = 54

def makeTempFile(types, query):
	""" make temp files for analysis
	:param types: indicates which types of authenticators and which stage we need to verify.
	:param query: indicates which exact property we need to verify.
	"""
	for type in types:
		for q in query:
			dir = 'FIDO\\results\\'+ type + '\\' + q
			if os.path.exists(dir):
				shutil.rmtree(dir,True)
				os.makedirs(dir)
			else:
				os.makedirs(dir)
	f1 = open('FIDO\lib.pvl','r')
	f2 = open('FIDO\\templib.pvl','w')
	all = f1.readlines()
	f2.writelines(all)
	f1.close()
	f2.close()
				
def analysis(t,types,delines,query):
	"""
	:param t: indicates the type of property we verify, 'S' represents the secrecy and 'A' represents the authentication
	:param types: indicates which types of authenticators and which stage we need to verify.
	:param delines: indicates which combinations of the adversary abilities we need to verify.
	:param query: indicates which exact property we need to verify.
	"""
	makeTempFile(types, query) #generate temp files for analysis
	log = open('recode.log', mode = 'a',encoding='utf-8')
	allnum = len(delines) #all lines we need to delete
	for type in types:
		if (t == 'S'): #analyze secrecy
			for q in query: 
				ifwrite = 0
				count = 0
				noprovecount = 0
				falsecount = 0
				securecount = 0
				toutcount = 0
				hypcount = 0
				ifwrite = 0
				secureSet = []
				noproveSet = []#to be used
				toutSet = []#to be used
				for delnum in range(allnum):#for any quantity of delete rows 
					for pre in itertools.combinations(delines, delnum): #for any  combinations
						if(SkipChoice(secureSet,pre)): #skip if in secureSet
							msg = 'skip in the secure subset'
						else: 
							result, outputl = ProVerifVerify(type, pre,query,q,0)
							if (result == 'prove'):					
								if (FindWayOut(pre,type,query,q)):
									falsecount = falsecount + 1
									msg = 'confidentiality cannot be proved but insecure' + str(falsecount)	
								else:
									noprovecount = noprovecount + 1
									msg = 'confidentiality cannot be proved' + str(noprovecount)
									ifwrite = 1				
							elif (result== 'false'):
								falsecount = falsecount + 1
								msg = 'confidentiality insecure' + str(falsecount)		
							elif (result== 'trace') :
								hypcount = hypcount + 1
								msg = 'found attacks with hypothesis ' + str(hypcount)	
								ifwrite = 1
							elif (result== 'true'):						
								securecount = securecount + 1
								msg = 'confidentiality secure' + str(securecount)
								secureSet.append(pre)
								ifwrite = 1
							elif (result== 'tout'):
								toutcount = toutcount + 1
								msg = 'confidentiality time out' + str(toutcount)
								ifwrite = 1
							else:
								print('error')
								print(outputl)
								ifwrite = 1
								input()
						#unified output
						print('count:'+str(count)+'type' +type +' ,query'+ q +',deleteNum'+str(delnum)+',combine' +str(pre) + msg,file=log)
						if ifwrite == 1:
							ifwrite = 0
							f3 = open('FIDO\\results\\'+ type + '\\' + q + '\\'+ str(count) + 'deleteNum' + str(delnum) + msg + '.pvl','w')
							f4 = open('FIDO\\query.pv','r')
							writel = f4.readlines()
							f3.writelines(writel)
							f3.writelines(str(outputl[-1000:-1]))
							f3.close()
							f4.close()	
						count = count + 1
		elif (t == 'A'): #analyze authentication properties
			for q in query: 
				count = 0
				noprovecount = 0
				falsecount = 0
				noinjfalsecount = 0
				securecount = 0
				toutcount = 0
				secureSet = []	
				noproveSet =  []
				toutSet =  []
				state = 0 # indicate if we need to nextly analyze the inj-event
				ifwrite = 0
				msg = ''
				msg2 = ''
				msg3= ''
				for delnum in range(allnum):
					for pre in itertools.combinations(delines, delnum): #for all combinations
						if(SkipChoice(secureSet,pre)):#skip if in secure Set
							msg = 'skip in secure subset'
						else: 					
							result, output1 = ProVerifVerify(type, pre,query,q,1)					
							if (result== 'false'):
								noinjfalsecount = noinjfalsecount + 1
								msg = 'non-inj insecure' + str(noinjfalsecount)						
							elif (result== 'prove'): 											
								msg = 'non-inj cannot be proved'
								state = 1
							elif (result== 'trace') :
								msg = 'non-inj cannot be proved but insecure'
								state = 1
							elif (result== 'true'):						
								msg = 'non-inj secure'
								state = 1
							elif (result== 'tout'):
								msg = 'non-inj time out' 
								ifwrite = 1
							else:
								print('error')
								print(output1[-1000:-1])
								input()
							if state == 1:#no result in non-inj, we need analyze inj-event
								state = 2
								for temp in toutSet: #if the analyze times out
									if set(temp).issubset(set(pre)):
										if (FindWayOut(pre,type,query,q)):
											falsecount = falsecount + 1
											msg3 = 'inj time out but insecure' + str(falsecount)		
											state = 0										
										else:
											toutcount = toutcount + 1
											msg3 = 'inj time out' 
											state == 2
										break
								if state == 2:
									state = 0
									result, output1 = ProVerifVerify(type, pre,query,q,0)
									if (result == 'false'):
										falsecount = falsecount + 1
										msg2 = 'inj insecure' + str(falsecount)	
									elif (result== 'trace') :
										falsecount = falsecount + 1
										msg2 = 'inj cannot be proved but insecure with hypothesis' + str(falsecount)	
									elif (result== 'prove'):
										noproveSet.append(pre)										
										if (FindWayOut(pre,type,query,q)):
											falsecount = falsecount + 1
											msg2 = 'inj cannot be proved but insecure' + str(falsecount)	
										else:
											noprovecount = noprovecount + 1
											msg2 = 'inj cannot be proved' + str(noprovecount)
											ifwrite = 1				
									elif (result== 'true'):						
										securecount = securecount + 1
										msg2 = 'inj secure' + str(securecount)
										ifwrite = 1
										secureSet.append(pre)
									elif(result == 'tout'):
										toutSet.append(pre)
										if (FindWayOut(pre,type,query,q)):
											falsecount = falsecount + 1
											msg2 = 'inj time out but insecure' + str(falsecount)					
										else:
											toutcount = toutcount + 1
											msg2 = 'inj time out' + str(toutcount)
											ifwrite = 1
									else:
										print('error')
										print(output1[-1000:-1])
										input()
						#unified output	
						print('count'+str(count)+'type' +type +' ,query'+ q +',deleteNum'+str(delnum)+',comine' +str(pre) + msg + ','+msg3 +','+ msg2,file=log)
						count  = count + 1
						if ifwrite == 1:							
							f3 = open('FIDO\\results\\'+ type + '\\' + q + '\\'+ str(count) + 'deleteNum'+ str(delnum) + msg + ','+msg3 +','+ msg2 + '.pvl','w')
							f4 = open('FIDO\\query.pv','r')
							writel = f4.readlines()
							f3.writelines(writel)
							f3.writelines(str(output1[-400:-1]))
							f3.close()
							f4.close()	
						ifwrite = 0	
						msg = ''
						msg2 = ''
						msg3 = ''
	log.close()	
		
def FindWayOut(pre,type,query,q):
	""" if the analyze times out, then we need to find a way to get results.
	"""
	ttt = pre + (chRR,chCUf,chMCf)
	result2 , output1= ProVerifVerify(type, ttt,query,q,0)
	if(result2  == 'false') or (result2 == 'trace'):
		return True
	ttt = pre + (chRR,)
	result2, output1 = ProVerifVerify(type, ttt,query,q,0)
	if(result2  == 'false') or (result2 == 'trace'):
		return True
	ttt = pre + (chMCf,)
	result2, output1 = ProVerifVerify(type, ttt,query,q,0)
	if(result2  == 'false') or (result2 == 'trace'):
		return True
	ttt = pre + (chUC,)
	result2, output1 = ProVerifVerify(type, ttt,query,q,0)
	if(result2  == 'false') or (result2 == 'trace'):
		return True
	ttt = pre + (chCUf,)
	result2, output1 = ProVerifVerify(type, ttt,query,q,0)
	if(result2  == 'false') or (result2 == 'trace'):
		return True
	print('actually cannot prove the query and cannot find attacks')
	return False
			
def ProVerifVerify(type, pre,query,q,iorn):
	addhttps = 0
	addUC = 0
	addCM = 0
	addMA = 0
	realquery = dict()
	if iorn == 1:
		injquery = dict()
		for qq in query:
			if (query[qq].find('inj-') != -1):
				injquery[qq] = query[qq].replace('inj-','')
		realquery = injquery.copy()
	else:
		realquery = query.copy()
	templetpath = 'FIDO\\'+ type +'.pv'
	if os.path.exists(templetpath):
		templetf = open(templetpath,'r')
	else:
		return False
	template = templetf.readlines()
	templetf.close()
	queryf = open('FIDO\query.pv','w')
	queryf.writelines(realquery[q]+'\n')
	lines = template.copy()
	for i in pre:    #for a spcefic combination,  choose some lines to delete and analyze.
		lines[i] = '(*' + lines[i][0:-1] + '*)' + '\n'
	#simplify the codes, the MITM attack is equal to the mutual public channel
	if (chRU  not in pre) and (chUR not in pre):
		lines[chRU]  = '(*' + lines[chRU][0:-1] + '*)' + '\n'
		lines[chUR]  = '(*' + lines[chUR][0:-1] + '*)' + '\n'
		addhttps = 1
	if (chUC not in pre) and  (chCU not in pre):
		lines[chUC]  = '(*' + lines[chUC][0:-1] + '*)' + '\n'
		lines[chCU]  = '(*' + lines[chCU][0:-1] + '*)' + '\n'
		addUC = 1
	if (chCM not in pre) and  (chMC not in pre):
		lines[chCM]  = '(*' + lines[chCM][0:-1] + '*)' + '\n'
		lines[chMC]  = '(*' + lines[chMC][0:-1] + '*)' + '\n'
		addCM = 1
	if (chMA not in pre) and  (chAM not in pre): 
		lines[chMA]  = '(*' + lines[chMA][0:-1] + '*)' + '\n'
		lines[chAM]  = '(*' + lines[chAM][0:-1] + '*)' + '\n'
		addMA = 1
	if (addhttps == 1):
		lines.insert(40,'	out(c,https);') 
	if (addUC == 1):
		lines.insert(40,'	out(c,UC);') 
	if (addCM == 1):
		lines.insert(40,'	out(c,CM);') 
	if (addMA == 1):
		lines.insert(40,'	out(c,MA);') 
	queryf.writelines(lines)
	queryf.close()
	output = Popen('proverif -lib "FIDO\\templib.pvl" FIDO\\query.pv', stdout=PIPE, stderr=PIPE)
	timer = Timer(30, lambda process: process.kill(), [output])
	try:
		timer.start()
		stdout, stderr = output.communicate()
		return_code = output.returncode
	finally:
		timer.cancel()
	result = stdout
	if (result[-400:-1].find(b'error') != -1): 
		final = 'error'
	elif (result[-600:-1].find(b'false') != -1) :
		final = 'false'
	elif (result[-2000:-1].find(b'hypothesis:') != -1) :
		final = 'trace'
	elif (result[-400:-1].find(b'prove') != -1):
		final = 'prove'
	elif (result[-400:-1].find(b'true') != -1):						
		final = 'true'
	else:
		final = 'tout'
	return final, result
	
def SkipChoice(secureSet,pre):
	# fun to find whether the pre is in the secure subset, if true, skip this query.
	for temp in secureSet:
		if set(temp).issubset(set(pre)):
			return True
	
queryRA = dict()
queryRA['RA-u'] ='query u:Username,a:Appid; inj-event(SFinishRegu(u)) ==> inj-event(AFinishRegu(u)).'
queryRA['RA-a'] = 'query u:Username,a:Appid; inj-event(SFinishRega(a)) ==> inj-event(AFinishRega(a)) .'
queryRA['RA-aa'] = 'query aa:AAID; inj-event(SFinishRegaa(aa)) ==> inj-event(AFinishRegaa(aa)).'
queryRA['RA-kh'] = 'query kh:bitstring; inj-event(SFinishRegkh(kh)) ==> inj-event(AFinishRegkh(kh)).'
queryRA['RA-au'] = 'query pauthkey:spkey; inj-event(SFinishRegpk(pauthkey)) ==> inj-event(AFinishRegpk(pauthkey)).'

queryRS = dict()
queryRS['RS-ak'] = 'query secret ak.'
queryRS['RS-id'] = 'query secret testkeyid.'
queryRS['RS-cn'] = 'query secret testauthcntr.'
queryRS['RS-au'] = 'query secret testSAuthenticationKey.'

queryRAR = {'RAR-u':'query u:Username,a:Appid,s:ServerData; inj-event(AFinishRegu(u)) ==> inj-event(SBeginReg(u,a,s)).'}
queryRAR['RAR-a'] = 'query u:Username,a:Appid,s:ServerData; inj-event(AFinishRega(a)) ==> inj-event(SBeginReg(u,a,s)).'

queryAA = dict()
queryAA['AA-u']= 'query u:Username,a:Appid; inj-event(SFinishAuthu(u)) ==> inj-event(AFinishAuthu(u)).'
queryAA['AA-a'] = 'query u:Username,a:Appid; inj-event(SFinishAutha(a)) ==> inj-event(AFinishAutha(a)).'
queryAA['AA-aa'] = 'query aa:AAID; inj-event(SFinishAuthaa(aa)) ==> inj-event(AFinishAuthaa(aa)).'
queryAA['AA-tr'] = 'query tr:Transaction; inj-event(SFinishAuthtr(tr)) ==> inj-event(AFinishAuthtr(tr)).'

queryAS = dict()
queryAS['AS-ak'] = 'query secret ak.'
queryAS['AS-cn'] = 'query attacker(new authcntr).'
queryAS['AS-au'] = 'query attacker(new SAuthenticationKey).'
queryAS['AS-tr'] = 'query attacker(new usertr).'

queryAAR = dict()
queryAAR['AAR-u'] = 'query u:Username,a:Appid; inj-event(AFinishAuthu(u)) ==> inj-event(SBeginAuth(u,a)).'
queryAAR['AAR-a'] = 'query u:Username,a:Appid; inj-event(AFinishAutha(a)) ==> inj-event(SBeginAuth(u,a)).'


# the combinations for each type of query to analyze.
RSlines = [31,32,33,chUR,chUC,chCU,chCM,chMCf,chMC,chMA,chAM]
ASlines = [30,31,32,33,chUR,chUC,chCU,chCM,chMCf,chMC,chMA,chAM]

RAlines = [31,32,33,chUR,chUC,chCU,chCM,chMCf,chMC,chMA,chAM]
AAlines = [30,31,32,33,chUR,chUC,chCU,chCM,chMCf,chMC,chMA,chAM]

# types to analyse.
typesRA = []
typesRA.append('R_1b')
typesRA.append('R_2b')
typesRA.append('R_1r')
typesRA.append('R_2r')

typesAA = []
typesAA.append('A_1b_empty')
typesAA.append('A_1b_setup')
typesAA.append('A_1r_empty')
typesAA.append('A_1r_setup')
typesAA.append('A_2b')
typesAA.append('A_2r')


# main process, to analyze each queries.
analysis('S',typesRA,RSlines,queryRS) # analyze secrecy in registration
analysis('S',typesAA,ASlines,queryAS)# analyze secrecy in authentication process
analysis('A',typesRA,RAlines,queryRA) # analyze authentication in registration from RP to autr.
analysis('A',typesRA,RAlines,queryRAR) # analyze authentication in registration from autr to RP.
analysis('A',typesAA,AAlines,queryAA) # analyze authentication in authentication from RP to autr.
analysis('A',typesAA,AAlines,queryAAR) # analyze authentication in authentication from autr to RP.
