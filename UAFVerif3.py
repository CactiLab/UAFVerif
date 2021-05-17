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
import re
from Content import Reg_1b_seta,Reg_1b_noa, Auth_1b_login_seta

class Result:
    def __init__(self,query_name,assumptions):
        self.query_name = query_name
        self.assumptions = assumptions
        self.content = query_name + assumptions

class Parser:
    def __init__(self,root_path):
        self.root_path = root_path
        self.result_pattern = re.compile("Query.*==>.*\.")
        self.secure_pattern = re.compile("Query.*==>.*true\.")
        self.event_pattern = re.compile("event\([^)]*\)")
    def parse(self,scene_name,proverif_result_path,final_result_path):
        proverif_result = ""
        with open(proverif_result_path, "r") as f:
            line = f.readline()
            if_last = False
            while line != "":
                if line.find('--------------------------------------------------------------') != -1:
                    if_last = True
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

    def get_query_and_assumptions(self,secure_result_item):
        if secure_result_item.find("attacker(") != -1:
            index = secure_result_item.find("==>")
        else:
            index = secure_result_item.find("||")
        assumptions = secure_result_item[index:] #assumptions
        query_name = secure_result_item[0:index-1]
        return query_name, assumptions
    def write_secure_result(self,scene_name,secure_set,final_result_path):
        with open(final_result_path, "a") as f:
            f.writelines(scene_name + ":\n\n")
            for item in secure_set:
                f.writelines(item.content + "\n")
            f.writelines("\n")

def proverif(root_path,query_path,result_path): # activate proverif and analyze the temp.pv file
    file_result = open(result_path, "w")
    p = Popen('proverif -lib "' + root_path + "UAF.pvl" + '" ' + query_path, stdout=file_result, stderr=file_result, shell=True)
    all_output_content = b""
    while p.poll() is None:
        print("正在运行" + time.strftime("%M:%S", time.localtime()) )
        time.sleep(4)
        #all_output_content += line
    file_result.close()
    #all_output_content, stderr = output.communicate()
    #return_code = output.returncode
    result = ""
    with open(result_path,"r") as f:
        line = f.readline()
        if_last = False
        while line != "":
            if line.find('--------------------------------------------------------------') != -1:
                if_last = True
            if if_last:
                result += line
            line = f.readline()
    return result # return the results


class Verif:
    def __init__(self,root_path,parser):
        self.root_path = root_path
        self.final_result_path = root_path + "LOG/final_result"
        self.parser = parser
        self.secure_queries = []
    def proverif_group_query(self, query_path, result_path):  # activate proverif and analyze the temp.pv file
        file_result = open(result_path, "w")
        p = Popen('proverif -lib "' + self.root_path + "UAF.pvl" + '" ' + query_path, stdout=file_result, stderr=file_result,
                  shell=True)
        all_output_content = b""
        while p.poll() is None:
            print("正在运行" + time.strftime("%M:%S", time.localtime()))
            time.sleep(4)
            # all_output_content += line
        file_result.close()
        # all_output_content, stderr = output.communicate()
        # return_code = output.returncode
        return True  # return the results

    def proverif(self, query_path):
        output = Popen('proverif -lib "' + root_path + "UAF.pvl" + '" ' + query_path, stdout=PIPE, stderr=PIPE)
        timer = Timer(20, lambda process: process.kill(), [output])
        try:
            timer.start()
            stdout, stderr = output.communicate()
            return_code = output.returncode
        finally:
            timer.cancel()
        i = stdout[0:-10].rfind(b'--------------------------------------------------------------')  # find last results
        result = stdout[i:-1]
        if result == b"" or len(result) == 0:
            result = stdout[-1000:-1]
        if (result.find(b'a trace has been found.') != -1):
            ret = 'false'
        elif (result.find(b'trace') != -1):
            ret = 'mayfalse'
        elif (result.find(b'error') != -1):
            ret = 'error'
        elif (result.find(b'false') != -1):
            ret = 'false'
        elif (result.find(b'hypothesis:') != -1):
            ret = 'trace'
        elif (result.find(b'prove') != -1):
            ret = 'prove'
        elif (result.find(b'true') != -1):
            ret = 'true'
        else:
            ret = 'tout'
        return ret, result  # return the results

    def generate_file_name(self,case):
        query_path = self.root_path + "Query/" + case.get_scene_name() + ".pv"
        with open(query_path, "w") as f:
            all_queries, content = case.get_content()
            f.writelines(all_queries)
            f.writelines(content)
        result_path = self.root_path + "LOG/" + case.get_scene_name() + ".result"
        return query_path, result_path

    def analyze(self,case,reboot):
        all_queries, content = case.get_content()
        counter = reboot
        log_file = open(root_path + "LOG/" + case.scene_name + ".log", "w")
        result_file = open(root_path + "LOG/" + "result.log", "a")
        while counter < len(all_queries):
            query = all_queries[counter]
            log_msg = str(counter).ljust(6)
            log_msg += case.scene_name + ", "
            log_msg += query.content + " "
            if self.is_query_in_secure_assumptions(query):
                log_msg += "jump in secure set"
            else:
                query_path = self.write_query_file(query,content,case)
                ret, result = self.proverif(query_path)
                if ret == "true":
                    self.add_secure_assumptions(query)
                    print(log_msg, file = result_file)
                    result_file.flush()
                log_msg += ret + " "
            log_msg += time.strftime('%Y.%m.%d %H:%M ', time.localtime(time.time()))
            print(log_msg, file = log_file)
            log_file.flush()
            counter += 1
            reboot = counter
        log_file.close()
        result_file.close()

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

def run(root_path):
    parser = Parser(root_path)
    verif = Verif(root_path,parser)
    verif.analyze_group_queries(Reg_1b_seta())
    verif.analyze_group_queries(Reg_1b_noa())

    #verif.analyze(Reg_1b_seta())
    #verif.analyze(Reg_1b_seta())
    #verif.analyze(Reg_1b_seta())
    #verif.analyze(Reg_1b_seta())
    #verif.analyze(Reg_1b_seta())
    #verif.analyze(Reg_1b_seta())
    #verif.analyze(Reg_1b_seta())
    return False
    pass

if __name__ == "__main__":
    root_path = os.getcwd() + "/"
    run(root_path)
