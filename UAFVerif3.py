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
    def __init__(self,query,assumptions,content):
        self.query = query
        self.assumptions = assumptions
        self.content = content
class Parser:
    def __init__(self,root_path):
        self.root_path = root_path
        self.result_path = root_path + "LOG/FINAL_RESULT.log"
        self.result_pattern = re.compile("Query.*==>.*\.")
        self.secure_pattern = re.compile("Query.*==>.*true\.")
        self.false_pattern = re.compile("Query.*==>.*proved|false\.")
        self.event_pattern = re.compile("event\([^)]*\)")
        self.secure_result_pattern = re.compile(".*Query.*==>.*true\.")
        self.secure_set = []
        self.false_set = []
        self.reboot()

    def reboot(self):
        if os.path.exists(self.result_path):
            with open(self.result_path,"r") as f:
                lines = "".join(f.readlines())
                all_valid_lines = self.secure_result_pattern.findall(lines)
                for line in all_valid_lines:
                    scene_name = line[0:line.find(",")]
                    query_name = line[line.find(",")+2:][0:line[line.find(",")+1:].find(",")-1]
                    content = line[line.find(",")+2:][line[line.find(",")+1:].find(",") + 1:]
                    assumptions = self.event_pattern.findall(self.get_query_and_assumptions(content))
                    self.secure_set.append(Query(scene_name,query_name,content,assumptions))


    def parse(self,scene_name,proverif_result_path,final_result_path):
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
        self.write_secure_result(scene_name,secure_set,final_result_path)

    def parser_record(self,query,proverif_result):
        secure_result = self.secure_pattern.findall(proverif_result)
        for secure_result_item in secure_result:
            assumptions_content = self.get_query_and_assumptions(secure_result_item)
            secure_assumptiosn = self.event_pattern.findall(assumptions_content)
            secure_query = Query(query.scene_name,query.query_name,secure_result_item,secure_assumptiosn)
            if self.is_in_secure_set(secure_query):
                continue
            else:
                self.secure_set.append(secure_query)
                with open(self.result_path,"a") as f:
                    f.writelines(secure_query.scene_name + ", ")
                    f.writelines(secure_query.query_name + ", ")
                    f.writelines(secure_query.content + "\n\n")
    def parser_record_false(self,query,proverif_result):
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
            if secure_query.is_same_query(cur_secure_query):
                if set(secure_query.assumptions).issubset(set(cur_secure_query.assumptions)):
                    return True
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
        if secure_result_item.find("attacker(") != -1:
            index = secure_result_item.find("==>") + 3
        else:
            index = secure_result_item.find("||") + 2
        assumptions = secure_result_item[index:] #assumptions
        #query_name = secure_result_item[0:index-1]
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
    def proverif_group_query(self, query_path):  # activate proverif and analyze the temp.pv file
        file_result = open(query_path + "temp.result", "w")
        p = Popen('proverif -lib "' + self.root_path + "UAF.pvl" + '" ' + query_path, stdout=file_result, stderr=file_result,shell=True)
        #stdout, stderr = p.communicate()
        while p.poll() is None:
            continue
            #print("正在运行" + time.strftime("%M:%S", time.localtime()))
        file_result.close()
        with open(query_path + "temp.result", "rb") as f:
            out = f.read()
        if p.poll() == 5:#timer kill
            ret = "abort or time out"
            result = out
        else:
            i = out[0:-10].rfind(b'--------------------------------------------------------------')  # find last results
            if i == -1:
                ret = "could not find ----- in result"
            else:
                ret = "True"
            result = out[i + 89:-70]
        return ret, str(result, encoding='utf-8')  # return the results

    def proverif3(self,query_path):
        output = os.popen('proverif -lib "' + root_path + "UAF.pvl" + '" ' + query_path)
    def proverif(self, query_path):#这个版本子进程或莫名其妙地卡住
        output = Popen('proverif -lib "' + root_path + "UAF.pvl" + '" ' + query_path, stdout=PIPE, stderr=PIPE)
        timer = Timer(300, lambda process: process.kill(), [output])
        try:
            timer.start()
            stdout, stderr = output.communicate()
            return_code = output.returncode
        finally:
            timer.cancel()
        with open(self.root_path + "LOG/all_log", "a") as LOG_FILE:
            LOG_FILE.writelines(str(stdout,encoding='utf-8'))
        if return_code != 0:
            ret = False
            result = stdout
        else:
            i = stdout[0:-10].rfind(b'--------------------------------------------------------------')  # find last results
            ret = True
            result = stdout[i+89:-70]
        return ret, str(result,encoding='utf-8')  # return the results

    def generate_file_name(self,case):
        query_path = self.root_path + "Query/" + case.get_scene_name() + ".pv"
        with open(query_path, "w") as f:
            all_queries, content = case.get_content()
            f.writelines(all_queries)
            f.writelines(content)
        result_path = self.root_path + "LOG/" + case.get_scene_name() + ".result"
        return query_path, result_path

    def analyze_group_queries(self,case):
        all_queries, content = case.get_content()
        query_path = root_path + "QUERY/" + case.get_scene_name() + ".pv"
        with open(query_path,"w") as query_file:
            query_file.writelines(all_queries)
            query_file.writelines(content)
        proverif_result_path = root_path + "LOG/" + case.get_scene_name() + ".result"
        result_path = root_path + "LOG/" + "result.log"
        self.proverif_group_query(query_path,proverif_result_path)
        self.parser.parse(case.get_scene_name(),proverif_result_path,result_path)

    def analyze_all(self,case,reboot):
        all_queries, content = case.get_content()
        counter = reboot
        scene_log_file = open(root_path + "LOG/" + case.scene_name + ".log", "a")
        result_path = root_path + "LOG/" + case.scene_name + ".result"
        while counter < len(all_queries):
            query = all_queries[counter]
            query_path = root_path + "QUERY/" + case.get_scene_name() + "-" + query.query_name + ".pv"
            log_content = ""
            log_content += str(counter) + ", " + query.scene_name + ", " + query.query_name + ", "
            jump_ret = self.parser.jump(query)
            if jump_ret == "true":
                log_content += "jump in secure set."
            #if jump_ret == "false":
                # og_content += "jump in false set."
            else:
                with open(query_path, "w") as query_file:
                    query_file.writelines(query.content)
                    query_file.writelines(content)
                ret,result = self.proverif_group_query(query_path)
                if ret != "True":
                    log_content += ret
                    shutil.copy(query_path, query_path + str(counter) + "abort.pv")
                    with open(query_path + str(counter) + "abort.pv", "a") as f:
                        f.writelines(result)
                else:
                    log_content += result
                    #if query.query_name[0] == 's':
                    self.parser.parser_record(query,result)
                    #else:
                        #self.parser.parser_record_false(query, result)
            log_content += str(time.strftime("%H:%M:%S", time.localtime()))
            log_content += "\n\n"
            scene_log_file.writelines(log_content)
            scene_log_file.flush()
            counter += 1
        scene_log_file.close()

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
    if not os.path.exists(root_path  + "QUERY/"):
        os.makedirs(root_path + "QUERY/")
    if not os.path.exists(root_path + "LOG/"):
        os.makedirs(root_path + "LOG/")

def run(root_path):
    makedir(root_path)
    parser = Parser(root_path)
    verif = Verif(root_path,parser)
    verif.analyze_all(Reg_1b_seta(),0)
    verif.analyze_all(Reg_1b_noa(),0)
    verif.analyze_all(Reg_2b_seta(),0)
    verif.analyze_all(Reg_2b_noa(),0)
    verif.analyze_all(Reg_1r_seta(),0)
    verif.analyze_all(Reg_1r_noa(),0)
    verif.analyze_all(Reg_2r_seta(),0)
    verif.analyze_all(Reg_2r_noa(),0)
    #verif.analyze_all(Auth_1b_login_seta(),0)
    #verif.analyze_all(Auth_1b_login_noa(),0)
    #verif.analyze_all(Auth_1b_stepup_seta(),0)
    #verif.analyze_all(Auth_1b_stepup_noa(),0)


if __name__ == "__main__":
    root_path = os.getcwd() + "/"
    run(root_path)
