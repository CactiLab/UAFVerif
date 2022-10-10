import itertools
import re
import time
from subprocess import Popen, PIPE
from threading import Timer
import os
import shutil

class Basic_Query:
    '''
    baisc information about the query
    '''
    def __init__(self,name,head,body):
        self.name = name  # the name of this query, e.g. "Aauth-tr",                                
        self.head = head  # the head part of this query, e.g. "query tr:Tr;"
        self.body = body  # the head part of this query, e.g. "inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr)))"
        self.content = head + body # the content of this query, e.g. "query tr:Tr;inj-event(RP_success_tr(tr)) ==> (inj-event(Autr_verify_tr(tr)) ==> inj-event(UA_launch_auth_tr(tr)))"


class Query:
    '''
    the query and the scenarios and assumptions that make the query true
    '''
    def __init__(self,scene_name,query_name,content,assumptions):
        self.scene_name = scene_name
        self.query_name = query_name
        self.content = content
        self.assumptions = assumptions


    def is_same_query(self, query):  # the same query is the two queries with the same name and in the same scene
        if self.scene_name == query.scene_name and self.query_name == query.query_name:
            return True
        return False


class Content:
    '''
    set the template content and generate the queries of each case
    '''
    assumption_events = [] # the events of assumptions
    basic_sec_queries = []     # the basic queries of the secrecy goal
    basic_auth_queries = []     # the basic queries of the secrecy goal
    group_sec_queries = []
    group_auth_queries = []
    process_codes = []     # the Proverif codes of the prptocol process
    scene_name = ''

    def __init__(self, assumptions, sec_queries, auth_queries, codes, scence_name):
        self.assumption_events = assumptions
        self.basic_sec_queries = sec_queries
        self.basic_auth_queries = auth_queries
        self.process_codes = codes
        self.scene_name = scence_name
        self.get_group_queries()
    

    def get_group_queries(self):
        for basic_sec_query in self.basic_sec_queries:  # iterate over all basic query statements
            temp_group_query = basic_sec_query.head + "\n"
            for num in range(len(self.assumption_events) + 1):  # get all combinaions of assumption_events
                for events in itertools.combinations((self.assumption_events), num):  # get the combinations with 'num' assumption_events
                    query_temp = basic_sec_query.body        # construct the body of the queries
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
            self.group_sec_queries.append(Query(self.scene_name, basic_sec_query.name, temp_group_query,[]))

        for basic_auth_query in self.basic_auth_queries:  # iterate over all basic query statements
            temp_group_query = basic_auth_query.head + "\n"
            for num in range(len(self.assumption_events) + 1):  # get all combinaions of assumption_events
                for events in itertools.combinations((self.assumption_events), num):  # get the combinations with 'num' assumption_events
                    query_temp = basic_auth_query.body        # construct the body of the queries
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
            self.group_auth_queries.append(Query(self.scene_name, basic_auth_query.name, temp_group_query, []))
            
    def get_content(self):
        return self.group_sec_queries, self.group_auth_queries, self.process_codes
    
    def get_scene_name(self):
        return self.scene_name


class Parser:
    def __init__(self, root_path, fulls, abbrs):
        self.root_path = root_path
        self.result_path = root_path + "LOG/FINAL_RESULT.log"
        self.result_path_simplify = root_path + "LOG/FINAL_RESULT_simplify.log"
        self.result_pattern = re.compile("Query.*\.")  # Query xxxxxxx.
        self.secure_pattern = re.compile("Query.*true\.")  # Query xxxxxxx true.
        self.false_pattern = re.compile("Query.*proved|false\.")  # Query xxxxxxx proved(false).
        self.event_pattern = re.compile("event\([^)]*\)")  # event(xxxxx characters that are not')')
        self.secure_result_pattern = re.compile(".*Query.*true\.")  # Query xxxxxxx true.
        self.full_assumps = fulls
        self.abbr_assumps = abbrs
        self.secure_set = []

    def simplify_lines(self, line):
        for i in range(0,len(self.full_assumps)):
            line = line.replace(self.full_assumps[i], self.abbr_assumps[i])

        line = line.replace("is true", "")
        pattern1 = re.compile("query.*==>")
        pattern2 = re.compile("query.*.")
        all_delete_line = pattern2.findall(line)
        for item in all_delete_line:
            line = line.replace(item, "")
        return line

    def parser_record(self,query,proverif_result):
        secure_result = self.secure_pattern.findall(proverif_result)  # find the true queries
        for secure_result_item in secure_result:                      # items with the form 'Query xxxxxxx true.'
            assumptions_content = self.get_query_and_assumptions(secure_result_item)  # determine the assumptions of the query
            secure_assumptions = self.event_pattern.findall(assumptions_content)      # find all str with the pattern 'event(xxxxx)' in assumptions
            secure_query = Query(query.scene_name,query.query_name,secure_result_item,secure_assumptions)
            if self.is_in_secure_set(secure_query):  # the current query is already in the secure_set
                continue  # go on
            else:  # the current query is not a subset of the secure_set
                self.secure_set.append(secure_query)
            line = secure_query.scene_name + ", " + secure_query.query_name + ", " + secure_query.content + "\n\n"
            with open(self.result_path,"a") as f: # write the result in result_log file
                f.writelines(line)
            with open(self.result_path_simplify, "a") as f:  # simplify the results in simplify_log file
                f.writelines(self.simplify_lines(line))

    def is_in_secure_set(self,cur_secure_query):
        for secure_query in self.secure_set:
            if secure_query.is_same_query(cur_secure_query): # two queries with the same scene_name and query_name
                if set(secure_query.assumptions).issubset(set(cur_secure_query.assumptions)):
                    return True  # the query can be satisfied with less assumptions
        return False

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


class Verif:
    def __init__(self,root_path,parser):
        self.root_path = root_path
        self.final_result_path = root_path + "LOG/final_result"
        self.parser = parser


    def proverif_sec_query(self, query_path):  # call proverif and analyze the temp.pv file
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
            # print("running" + time.strftime("%M:%S", time.localtime()))
        file_result.close()
        with open(query_path + "temp.result", "rb") as f:
            out = f.read()
            # print(out)
        if p.poll() != 0: # timer kill
            ret = "abort or time out"
            result = out
        else:
            i = out[0:-10].rfind(b'--------------------------------------------------------------')  # find last results
            if i == -1:
                ret = "could not find ----- in result"
                result = out
            else:
                ret = "True" # this query can be proved, either be proved as true or false 
                result = out[i + 89:-70]
        return ret, str(result, encoding='utf-8')  # return the results


    def proverif_auth_query(self, query_path):  # call proverif and analyze the temp.pv file
        file_result = open(query_path + "temp.result", "w")
        # write the output and error in file_result
        p = Popen('proverif -lib "' + self.root_path + "UAF+.pvl" + '" ' + query_path, stdout=file_result, stderr=file_result,shell=True)
        timer = Timer(800, lambda process: process.kill(), [p])
        try:
            timer.start()
            while p.poll() is None:
                continue
        finally:
            timer.cancel()
            # print("running" + time.strftime("%M:%S", time.localtime()))
        file_result.close()
        with open(query_path + "temp.result", "rb") as f:
            out = f.read()
            # print(out)
        if p.poll() != 0: # timer kill
            ret = "abort or time out"
            result = out
        else:
            i = out[0:-10].rfind(b'--------------------------------------------------------------')  # find last results
            if i == -1:
                ret = "could not find ----- in result"
                result = out
            else:
                ret = "True" # this query can be proved, either be proved as true or false
                result = out[i + 89:-70]
        return ret, str(result, encoding='utf-8')  # return the results

    def analyze_all(self, case):
        # print('11111111111111111111111111')
        group_sec_queries, group_auth_queries, process_code = case.get_content() # get the group queries and the code of protocol process
        scene_log_file = open(self.root_path + "LOG/" + case.scene_name + ".log", "a")
        result_path = self.root_path + "LOG/" + case.scene_name + ".result"
        counter = 0
        
        while counter < len(group_sec_queries): # all group queries
            query = group_sec_queries[counter]  # for each group query
            query_path = self.root_path + "QUERY/" + case.get_scene_name() + "-" + query.query_name + ".pv"
            log_content = ""
            log_content += str(counter) + ", " + query.scene_name + ", " + query.query_name + ", "
            with open(query_path, "w") as query_file:  # generate a query file
                query_file.writelines(query.content)   # write the query codes in file
                query_file.writelines(process_code)            # write the protocol process codes in file
                # print('2222222222222222222222')
            # ret: brief return value; result: the stdout result
            ret, result = self.proverif_sec_query(query_path)  
            if ret != "True":
                log_content += ret
                error_path = self.root_path + "/ERROR/" + case.get_scene_name() + "-" + query.query_name + "-" + str(counter) + "-error.pv"
                shutil.copy(query_path, error_path)  # copy the content in query_path to error_path
                with open(error_path, "a") as f:  # open the file with 'append' mode and write the stdout result
                    f.writelines(result)
                print(error_path + "\n")
            else:
                log_content += result
                self.parser.parser_record(query,result)
                
            log_content += str(time.strftime("%H:%M:%S", time.localtime()))
            log_content += "\n\n"
            scene_log_file.writelines(log_content)
            scene_log_file.flush()
            counter += 1
        counter = 0

        while counter < len(group_auth_queries): # all group queries
            query = group_auth_queries[counter]  # for each group query
            query_path = self.root_path + "QUERY/" + case.get_scene_name() + "-" + query.query_name + ".pv"
            log_content = ""
            log_content += str(counter) + ", " + query.scene_name + ", " + query.query_name + ", "
            
            with open(query_path, "w") as query_file:  # generate a query file
                query_file.writelines(query.content)   # write the query codes in file
                query_file.writelines(process_code)            # write the protocol process codes in file
            # ret: brief return value; result: the stdout result
            ret, result = self.proverif_auth_query(query_path)  
            if ret != "True":
                log_content += ret
                error_path = self.root_path + "/ERROR/" + case.get_scene_name() + "-" + query.query_name + "-" + str(counter) + "-error.pv"
                shutil.copy(query_path, error_path)  # copy the content in query_path to error_path
                with open(error_path, "a") as f:  # open the file with 'append' mode and write the stdout result
                    f.writelines(result)
                print(error_path + "\n")
            else:
                log_content += result
                self.parser.parser_record(query,result)
                
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


def makedir(root_path):
    '''
    Clear/create the folders for .pv files, error records, and log files
    '''
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

def read_assumptions(assumption_file_path):
    fulls = []
    abbrs = []
    assumption_file = open(assumption_file_path, "r")
    lines = assumption_file.readlines()

    for line in lines:
        full_abbr = line.split(',')
        fulls.append(full_abbr[0].strip())
        abbrs.append(full_abbr[1].strip())
    assumption_file.close()
    return fulls, abbrs

def read_process(process_file_path):
    process_file = open(process_file_path, "r")
    lines = process_file.readlines()
    process_file.close()
    return lines

def read_queries(query_file_path):
    queries = []
    query_file = open(query_file_path, "r")
    lines = query_file.readlines()
    for line in lines:
        query = []
        parts = line.split('|')
        for part in parts:
            query.append(part.strip())
        queries.append(query)
    query_file.close()
    return queries

def read_files(root_path):
    '''
    read the protocol process codes for each senario
    read secrecy queries and authentication queries
    read the full name and abbreviations of assumptions
    '''
    assumption_path = root_path + "Src/Assumptions"
    process_path = root_path + "Src/Process"
    queries_path = root_path + "Src/Queries"
    process_code_list = []
    all_auth_queries = []
    all_sec_queries = []

    # all paths are available
    if not os.path.exists(assumption_path) or not os.listdir(assumption_path):
        print("Please set the assumptions under the folder /Src/Assumptions.")
    elif not os.path.exists(process_path) or not os.listdir(process_path):
        print("Please put the ProVerif code of protocol process under the folder /Src/Process.")
    elif not os.path.exists(queries_path) or not os.listdir(queries_path):
        print("Please put the secrecy queries and authentication queries under the folder /Src/Queries.")
    else:
        assumption_file_list = os.listdir(assumption_path)
        if len(assumption_file_list) > 1:
            print("Too many files given, please put security assumptions in one file.")
        else:
            assumption_file_path = assumption_path + '/' + assumption_file_list[0]
            fulls, abbrs = read_assumptions(assumption_file_path)

        process_file_list = os.listdir(process_path)
        for process_file in process_file_list:
            process_file_path = process_path + '/' + process_file
            lines = read_process(process_file_path)
            process_code_list.append(lines)

        query_folder_list = os.listdir(queries_path)
        if len(query_folder_list) > len(process_file_list):
            print("Too many folders are given, please only put the queries correspond to the scenarios in the folder /Src/Process.")
        else:
            for i in range(0,len(query_folder_list)):
                query_file_list = os.listdir(queries_path + '/' + query_folder_list[i])
                authquery_file_path = queries_path + '/' + query_folder_list[i] + '/' + query_file_list[0]
                secquery_file_path = queries_path + '/' + query_folder_list[i] + '/' + query_file_list[1]
                auth_queries = read_queries(authquery_file_path)
                sec_queries = read_queries(secquery_file_path)
                all_auth_queries.append(auth_queries)
                all_sec_queries.append(sec_queries)
        return fulls, abbrs, process_code_list, all_auth_queries, all_sec_queries, query_folder_list


def items_to_queries(item_list):
    query_list = []
    for item in item_list:
        query = Basic_Query(item[0],item[1],item[2])
        query_list.append(query)
    return query_list


def run(root_path):
    makedir(root_path)
    fulls, abbrs, process_code_list, all_auth_query_items, all_sec_query_items, case_names = read_files(root_path)

    parser = Parser(root_path, fulls, abbrs)
    verif = Verif(root_path, parser)

    for i in range(0,len(case_names)):
        auth_queries = items_to_queries(all_auth_query_items[i])
        sec_queries = items_to_queries(all_sec_query_items[i])
        case = Content(fulls, sec_queries, auth_queries, process_code_list[i], case_names[i])
        verif.analyze_all(case)


if __name__ == "__main__":
    # print('Start_Time' + str(time.strftime("%H:%M:%S", time.localtime())) + '\n')
    root_path = os.getcwd() + "/"
    run(root_path)
    
    # print('End_Time' + str(time.strftime("%H:%M:%S", time.localtime())) + '\n')