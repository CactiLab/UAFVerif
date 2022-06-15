from asyncore import write
import itertools
import os
import shutil
import sys
import threading
import getopt
import time
from threading import Timer
from subprocess import Popen, PIPE
import pickle
import shutil
import re
from Content import *


class Result:
    def __init__(self, query, assumptions, content):
        self.query = query
        self.assumptions = assumptions
        self.content = content


class Parser:
    def __init__(self, root_path):
        self.root_path = root_path
        self.result_path = root_path + "LOG/FINAL_RESULT.log"
        self.result_path_simplify = root_path + "LOG/FINAL_RESULT_simplify.log"
        self.result_pattern = re.compile("Query.*\.")              # Query xxxxxxx.
        self.secure_pattern = re.compile("Query.*true\.")          # Query xxxxxxx true.
        self.false_pattern = re.compile("Query.*proved|false\.")   # Query xxxxxxx proved(false).
        self.event_pattern = re.compile("event\([^)]*\)")          # event(xxxxx characters that are not')')
        self.secure_result_pattern = re.compile(".*Query.*true\.") # Query xxxxxxx true.
        self.secure_set = []
        self.false_set = []
        self.reboot()

    def reboot(self):
        if os.path.exists(self.result_path):
            with open(self.result_path,"r") as f:
                lines = "".join(f.readlines())
                all_valid_lines = self.secure_result_pattern.findall(lines)  # find all matches with pattern 'Query xxxxxxx true.'
                for line in all_valid_lines:
                    scene_name = line[0:line.find(",")]
                    query_name = line[line.find(",")+2:][0:line[line.find(",")+1:].find(",")-1]
                    content = line[line.find(",")+2:][line[line.find(",")+1:].find(",") + 1:]
                    assumptions = self.event_pattern.findall(self.get_query_and_assumptions(content))
                    self.secure_set.append(Query(scene_name, query_name, content, assumptions))

    """ def parse(self,scene_name,proverif_result_path,final_result_path):
        proverif_result = ""
        with open(proverif_result_path, "r") as f:
            line = f.readline()
            if_last = False
            while line != "":
                if line.find('--------------------------------------------------------------') != -1:
                    if_last = not if_last
                if if_last:
                    proverif_result += line
                line = f.readline()
        secure_result = self.secure_pattern.findall(proverif_result)
        secure_set = []
        for secure_result_item in secure_result:
            query_name,assumptions = self.get_query_and_assumptions(secure_result_item)
            temp_secure_set = self.event_pattern.findall(assumptions)
            if_in_secure_set = False
            for secure_item in secure_set:
                if query_name != secure_item.query_name:
                    continue
                secure_item_set = self.event_pattern.findall(secure_item.assumptions)
                if set(secure_item_set).issubset(set(temp_secure_set)):
                    if_in_secure_set = True
            if if_in_secure_set == False:
                secure_set.append(Result(query_name, assumptions))
        self.write_secure_result(scene_name,secure_set,final_result_path) """

    def parser_record(self,query,proverif_result):
        secure_result = self.secure_pattern.findall(proverif_result)  # find the true queries
        for secure_result_item in secure_result:                      # items with the form 'Query xxxxxxx true.'
            assumptions_content = self.get_query_and_assumptions(secure_result_item)  # determine the assumptions of the query
            secure_assumptions = self.event_pattern.findall(assumptions_content)      # find all str with the pattern 'event(xxxxx)' in assumptions
            secure_query = Query(query.scene_name,query.query_name,secure_result_item,secure_assumptions)
            if self.is_in_secure_set(secure_query): # the current query is already in the secure_set
                continue  # go on 
            else:  # the current query is not a subset of the secure_set
                self.secure_set.append(secure_query)
                line = secure_query.scene_name + ", " + secure_query.query_name + ", " + secure_query.content + "\n\n"
                with open(self.result_path,"a") as f: # write the result in result_log file
                    f.writelines(line)
                with open(self.result_path_simplify, "a") as f: # simplify the results in simplify_log file
                    f.writelines(self.simplify_lines(line)) 

    def parser_record_single(self,secure_query):
        self.secure_set.append(secure_query)
        line = secure_query.scene_name + ", " + secure_query.query_name + ", " + secure_query.content
        for assumption in secure_query.assumptions:
            line += assumption + "&"
        line += "\n\n"
        with open(self.result_path, "a") as f:
            f.writelines(line)
        with open(self.result_path_simplify, "a") as f:
            f.writelines(self.simplify_lines(line))
    
    # replace the assumptions from events to abbreviations
    def simplify_lines(self, line):
        line = line.replace("event(malicious_US_to_RP)","SW")      # malicious UAF Server communicates with Web Server
        line = line.replace("event(malicious_RP_to_US)", "WS")     # malicious Web Server communicates with UAF Server
        line = line.replace("event(malicious_UA_to_RP)", "UW")     # malicious User Agent communicates with Web Server
        line = line.replace("event(malicious_RP_to_UA)", "WU")     # malicious Web Server communicates with User Agent
        line = line.replace("event(malicious_UA_to_UC)", "UC")     # malicious User Agent communicates with UAF Client
        line = line.replace("event(malicious_UC_to_UA)", "CU")     # malicious UAF Client communicates with User Agent
        line = line.replace("event(malicious_UC_to_ASM)", "CM")    # malicious UAF Client communicates with ASM
        line = line.replace("event(malicious_ASM_to_UC)", "MC")    # malicious ASM communicates with 
        line = line.replace("event(malicious_Autr_to_ASM)", "AM")  # malicious Authnr communicates with ASM
        line = line.replace("event(malicious_ASM_to_Autr)", "MA")  # malicious ASM communicates with Authnr
        line = line.replace("event(leak_token)", "tok")            # attacker knows ASM_Token
        line = line.replace("event(leak_skau)", "skau")            # attacker knows skAU
        line = line.replace("event(leak_cntr)", "cntr")            # attacker knows CNTR
        line = line.replace("event(leak_kid)", "kid")              # attacker knows KeyID
        line = line.replace("event(leak_kw)", "kw")                # attacker knows kW
        line = line.replace("is true", "")
        pattern1 = re.compile("query.*==>")
        pattern2 = re.compile("query.*.")
        all_delete_line = pattern2.findall(line)
        for item in all_delete_line:
            line = line.replace(item,"")
        return line

    def parser_record_false(self, query, proverif_result):
        false_result = self.false_pattern.findall(proverif_result)
        for false_result_item in false_result:
            assumptions_content = self.get_query_and_assumptions(false_result_item)
            secure_assumptiosn = self.event_pattern.findall(assumptions_content)
            false_query = Query(query.scene_name, query.query_name, false_result_item, secure_assumptiosn)
            if self.is_in_false_set(false_query):
                continue
            else:
                self.false_set.append(false_query)
                with open(self.result_path, "a") as f:
                    f.writelines(false_query.scene_name + ", ")
                    f.writelines(false_query.query_name + ", ")
                    f.writelines(false_query.content + "\n\n")

    def is_in_secure_set(self,cur_secure_query):
        for secure_query in self.secure_set:
            if secure_query.is_same_query(cur_secure_query): # two queries with the same scene_name and query_name
                if set(secure_query.assumptions).issubset(set(cur_secure_query.assumptions)):
                    return True  # the query can be satisfied with less assumptions
        return False

    def is_in_false_set(self,cur_query):
        for false_query in self.false_set:
            if false_query.is_same_query(cur_query):
                if set(cur_query.assumptions).issubset(set(false_query.assumptions)):
                    return True
        return False

    def jump(self,query):
        if self.is_in_secure_set(query):
            return "true"
        if self.is_in_false_set(query):
            return "false"
        return "nojump"

    def get_query_and_assumptions(self,secure_result_item):
        if secure_result_item.find("attacker") != -1:  # secrecy query result
            index = secure_result_item.find("==>")    
            if index == -1:  # result with no attacker ability assumptions
                assumptions = ""
                return assumptions
            else:            # result with one and more attacker ability assumptions
                begin = index + 3
        else:  # authentication query result
            index = secure_result_item.find("||")
            begin = index + 2
        assumptions = secure_result_item[index:]  # assumptions
        # query_name = secure_result_item[0:index-1]
        return assumptions

    def write_secure_result(self,scene_name,secure_set,final_result_path):
        with open(final_result_path, "a") as f:
            f.writelines(scene_name + ":\n\n")
            for item in secure_set:
                f.writelines(item.content + "\n")
            f.writelines("\n")


class Verif:
    def __init__(self,root_path,parser):
        self.root_path = root_path
        self.final_result_path = root_path + "LOG/final_result"
        self.reboot_number_path = root_path + "LOG/final_result"
        self.parser = parser
        self.secure_queries = []

    def proverif_group_query(self, query_path):  # call proverif and analyze the temp.pv file
        file_result = open(query_path + "temp.result", "w")
        # write the output and error in file_result
        p = Popen('proverif -lib "' + self.root_path + "UAF+.pvl" + '" ' + query_path, stdout=file_result, stderr=file_result,shell=True)
        timer = Timer(40, lambda process: process.kill(), [p])
        try:
            timer.start()
            while p.poll() is None:
                continue
        finally:
            timer.cancel()
            #print("running" + time.strftime("%M:%S", time.localtime()))
        file_result.close()
        with open(query_path + "temp.result", "rb") as f:
            out = f.read()
        if p.poll() != 0:#timer kill
            ret = "abort or time out"
            result = out
        else:
            i = out[0:-10].rfind(b'--------------------------------------------------------------')  # find last results
            if i == -1:
                ret = "could not find ----- in result"
                result = out
            else:
                ret = "True"
                result = out[i + 89:-70]
        return ret, str(result, encoding='utf-8')  # return the results

    def proverif(self, query_path):
        file_result = open(query_path + "temp.result", "w")
        # write the output and error in file_result
        p = Popen('proverif -lib "' + self.root_path + "UAF+.pvl" + '" ' + query_path, stdout=file_result, stderr=file_result,shell=True)
        timer = Timer(60, lambda process: process.kill(), [p])
        try:
            timer.start()
            while p.poll() is None:
                continue
        finally:
            timer.cancel()
            #print("running" + time.strftime("%M:%S", time.localtime()))
        file_result.close()
        with open(query_path + "temp.result", "rb") as f:
            out = f.read()
        if p.poll() != 0:#timer kill
            ret = "abort or time out"
            result = out
        else:
            i = out[0:-10].rfind(b'--------------------------------------------------------------')  # find last results
            if i == -1:
                ret = "could not find ----- in result"
                result = out
            else:
                ret = "True"
                result = out[i + 89:-70]
        return ret, str(result, encoding='utf-8')  # return the results

    def generate_file_name(self,case):
        query_path = self.root_path + "Query/" + case.get_scene_name() + ".pv"
        with open(query_path, "w") as f:
            all_queries, content = case.get_content()
            f.writelines(all_queries)
            f.writelines(content)
        result_path = self.root_path + "LOG/" + case.get_scene_name() + ".result"
        return query_path, result_path

    def analyze_all(self, case, reboot):
        secrecy_queries, auth_queries, content = case.get_content()
        counter = reboot
        scene_log_file = open(root_path + "LOG/" + case.scene_name + ".log", "a")
        result_path = root_path + "LOG/" + case.scene_name + ".result"
        while counter < len(secrecy_queries): # all secrecy queries
            
            query = secrecy_queries[counter] # for each secrecy queries
            query_path = root_path + "QUERY/" + case.get_scene_name() + "-" + query.query_name + ".pv"
            log_content = ""
            log_content += str(counter) + ", " + query.scene_name + ", " + query.query_name + ", "
            jump_ret = self.parser.jump(query)
            if jump_ret == "true":
                log_content += "jump in secure set."
            #if jump_ret == "false":
                # og_content += "jump in false set."
            else:
                with open(query_path, "w") as query_file:  # generate a query file
                    query_file.writelines(query.content)   # write the query in file
                    query_file.writelines(content)         # write the main contents in file
                # ret: brief return value; result: the stdout result
                ret, result = self.proverif_group_query(query_path)  
                if ret != "True":
                    log_content += ret
                    error_path = root_path + "/ERROR/" + case.get_scene_name() + "-" + query.query_name + "-" + str(counter) + "-error.pv"
                    shutil.copy(query_path, error_path)  # copy the content in query_path to error_path
                    with open(error_path, "a") as f:  # open the file with 'append' mode and write the stdout result
                        f.writelines(result)
                    print(error_path + "\n")
                else:
                    log_content += result
                    # if query.query_name[0] == 's':
                    self.parser.parser_record(query,result)
                    # else:
                    # self.parser.parser_record_false(query, result)
            log_content += str(time.strftime("%H:%M:%S", time.localtime()))
            log_content += "\n\n"
            scene_log_file.writelines(log_content)
            scene_log_file.flush()
            counter += 1
        counter = reboot 
        unbound_state = False  # speed up our analysis within a single session(true for unbounded sessions)
        while counter < len(auth_queries):
            query = auth_queries[counter]
            query_path = root_path + "QUERY/" + case.get_scene_name() + "-" + query.query_name + ".pv"
            log_content = ""
            log_content += str(counter) + ", " + query.scene_name + ", " + query.query_name + ", "
            jump_ret = self.parser.jump(query)
            if jump_ret == "true":
                log_content += "jump in secure set."
            else:
                with open(query_path, "w") as query_file:
                    temp_content = content[:]
                    for assumption in query.assumptions:
                        for i in range(len(temp_content)):
                            if temp_content[i].find(assumption[6:-1]) != -1:  # remove the assumption of this case
                                if temp_content[i].find("*)") != -1:
                                    temp_content[i] = "" + temp_content[i][:-1] + "\n"
                                else:
                                    temp_content[i] = "(*" + temp_content[i][:-1] + "*)\n"
                                break
                    if unbound_state is False:  # with speed up version
                        for i in range(len(temp_content)):
                            if temp_content[i].find("!system") != -1:
                                temp_content[i] = temp_content[i].replace("!", "")
                                break
                    query_file.writelines(query.content)
                    query_file.writelines(temp_content)
                ret, result = self.proverif(query_path)
                if ret != "True":
                    log_content += ret
                    error_path = root_path + "/ERROR/" + case.get_scene_name() + "-" + query.query_name + "-" + str(
                        counter) + "-error.pv"
                    shutil.copy(query_path, error_path)
                    with open(error_path, "a") as f:
                        f.writelines(result)
                    print(error_path + "\n")
                else:
                    log_content += result
                    if result.find("true") != -1:
                        if unbound_state is False:
                            unbound_state = True
                            counter -= 1
                        else:
                            unbound_state = False
                            self.parser.parser_record_single(query)
            log_content += str(time.strftime("%H:%M:%S", time.localtime()))
            log_content += "\n\n"
            scene_log_file.writelines(log_content)
            scene_log_file.flush()
            counter += 1
        # scene_log_file.close()
        counter = reboot
        while counter < len(auth_queries):
            break
            query = auth_queries[counter]
            query_path = root_path + "QUERY/" + case.get_scene_name() + "-" + query.query_name + ".pv"
            log_content = ""
            log_content += str(counter) + ", " + query.scene_name + ", " + query.query_name + ", "
            jump_ret = self.parser.jump(query)
            if jump_ret == "true":
                log_content += "jump in secure set."
            #if jump_ret == "false":
                #log_content += "jump in false set."
            else:
                with open(query_path, "w") as query_file: # generate one file for each query
                    query_file.writelines(query.content)
                    query_file.writelines(content)
                ret,result = self.proverif(query_path)
                if ret != "True":
                    log_content += ret
                    error_path = root_path + "/ERROR/" + case.get_scene_name() + "-" + query.query_name + "-" + str(
                        counter) + "-error.pv"
                    shutil.copy(query_path, error_path)
                    with open(error_path, "a") as f:
                        f.writelines(result)
                else:
                    log_content += result
                    self.parser.parser_record(query, result)
            log_content += str(time.strftime("%H:%M:%S", time.localtime()))
            log_content += "\n\n"
            scene_log_file.writelines(log_content)
            scene_log_file.flush()
            counter += 1

    def is_query_in_secure_assumptions(self,query):
        for secure_query in self.secure_queries:
            if secure_query.scene_name == query.scene_name and secure_query.query_name == query.query_name and set(secure_query.assumptions).issubset(set(query.assumptions)):
                return True
        return False

    def add_secure_assumptions(self,query):
        self.secure_queries.append(query)

    def write_query_file(self,query,content,case):
        query_path = self.root_path + "Query/" + case.get_scene_name() + ".pv"
        with open(query_path, "w") as f:
            f.writelines(query.content)
            f.writelines(content)
        return query_path


def makedir(root_path):
    if os.path.exists(root_path + "QUERY/"):
        shutil.rmtree(root_path + "QUERY/")
    if os.path.exists(root_path + "ERROR/"):
        shutil.rmtree(root_path + "ERROR/")
    if os.path.exists(root_path + "LOG/"):
        shutil.rmtree(root_path + "LOG/")

    if not os.path.exists(root_path + "QUERY/"):  # the path of .pv files
        os.makedirs(root_path + "QUERY/")
    if not os.path.exists(root_path  + "ERROR/"): # the path of error files
        os.makedirs(root_path + "ERROR/")
    if not os.path.exists(root_path + "LOG/"):
        os.makedirs(root_path + "LOG/")


def run(root_path):
    makedir(root_path)
    parser = Parser(root_path)
    verif = Verif(root_path, parser)
    verif.analyze_all(Reg_1b_seta(), 0)
    verif.analyze_all(Reg_1b_noa(), 0)
    verif.analyze_all(Reg_2b_seta(), 0)
    verif.analyze_all(Reg_2b_noa(), 0)
    verif.analyze_all(Reg_1r_seta(), 0)
    verif.analyze_all(Reg_1r_noa(), 0)
    verif.analyze_all(Reg_2r_seta(), 0)
    verif.analyze_all(Reg_2r_noa(), 0)
    verif.analyze_all(Auth_1b_login_seta(), 0)
    verif.analyze_all(Auth_1b_login_noa(), 0)
    verif.analyze_all(Auth_1b_stepup_seta(), 0)
    verif.analyze_all(Auth_1b_stepup_noa(), 0)
    verif.analyze_all(Auth_2b_stepup_seta(), 0)
    verif.analyze_all(Auth_2b_stepup_noa(), 0)
    verif.analyze_all(Auth_1r_login_seta(), 0)
    verif.analyze_all(Auth_1r_login_noa(), 0)
    verif.analyze_all(Auth_1r_stepup_seta(), 0)
    verif.analyze_all(Auth_1r_stepup_noa(), 0)
    verif.analyze_all(Auth_2r_stepup_seta(), 0)
    verif.analyze_all(Auth_2r_stepup_noa(), 0)


if __name__ == "__main__":
    # print('Start_Time' + str(time.strftime("%H:%M:%S", time.localtime())) + '\n')
    root_path = os.getcwd() + "/"
    run(root_path)
    # print('End_Time' + str(time.strftime("%H:%M:%S", time.localtime())) + '\n')
