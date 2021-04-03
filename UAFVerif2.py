import itertools
import os
import sys
import threading
import getopt
import time
from threading import Timer
from subprocess import Popen, PIPE
from Content import Reg_content, Auth_content
from Reg import Reg_1b_seta,Reg_1b_noa,Reg_2b_seta,Reg_2b_noa,Reg_1r_seta,Reg_1r_noa,Reg_2r_seta,Reg_2r_noa
from Auth import Auth_1b_seta_login,Auth_1b_seta_stepup,Auth_1b_noa_login,Auth_1b_noa_stepup,Auth_2b_seta,Auth_2b_noa,Auth_1r_seta_login,Auth_1r_seta_stepup,Auth_1r_noa_login,Auth_1r_noa_stepup,Auth_2r_seta,Auth_2r_noa

class Generator:
    def __init__(self,content_class,target_scene):
        self.content_class = content_class
        self.target_scene = target_scene
        self.all_leak = []
        self.all_malicious = []
        self.all_queries = target_scene.get_queries()
        for delnum in range(len(target_scene.get_leak_fields()) + 1):
            for row_numbers in itertools.combinations(range(len(target_scene.get_leak_fields())), delnum):
                temp = []
                for i in row_numbers:
                    temp.append(target_scene.get_leak_fields()[i])
                self.all_leak.append((row_numbers,temp))
        for delnum in range(len(target_scene.get_malicious_entities()) + 1):
            for row_numbers in itertools.combinations(range(len(target_scene.get_malicious_entities())), delnum):
                temp = []
                for i in row_numbers:
                    temp.append(target_scene.get_malicious_entities()[i])
                self. all_malicious.append((row_numbers,temp))
        self.all_malicious.reverse()
        self.all_leak.reverse()
        self.query_num = len(self.all_queries)
        self.leak_num = len(self.all_leak)
        self.malicious_num = len(self.all_malicious)
        self.cur_q = 0
        self.cur_l = 0
        self.cur_m = -1
    def generate_case(self):
        ret = 0
        target_content = self.content_class()
        if self.cur_m >= self.malicious_num - 1:
            self.cur_m = 0
            if(self.cur_l >= self.leak_num - 1):
                self.cur_l = 0
                if(self.cur_q >= self.query_num - 1):
                    return -1, target_content
                else:
                    ret = 1
                    self.cur_q = self.cur_q + 1
            else:
                self.cur_l = self.cur_l + 1
        else:
            self.cur_m = self.cur_m + 1
        target_content.add_specific_operation(self.target_scene.get_specific_operation())
        target_content.add_honest_entities(self.target_scene.get_honest_entities(), self.target_scene.scene_name)
        target_content.add_leak_fields(self.all_leak[self.cur_l][1],self.all_leak[self.cur_l][0])
        target_content.add_malicious_entities(self.all_malicious[self.cur_m][1],self.all_malicious[self.cur_m][0])
        target_content.add_open_rp(self.target_scene.get_open_rp())
        target_content.add_query(self.all_queries[self.cur_q].query, self.all_queries[self.cur_q].name)
        return ret, target_content

class Jump:
    def __init__(self):
        self.secure_set = []
    def add_secure_scene(self,target_scene):
        self.secure_set.append(target_scene)
    def is_secure(self,target_scene):
        for secure_scene in self.secure_set:
            if secure_scene.scene_name == target_scene.scene_name and secure_scene.query_name == target_scene.query_name:
                if (set(target_scene.leak_lines).issubset(set(secure_scene.leak_lines))) and (set(target_scene.malicious_lines).issubset(set(secure_scene.malicious_lines))):
                    return True
        return False

def proverif(root_path,query_path): # activate proverif and analyze the temp.pv file
    output = Popen('proverif -lib "' + root_path + "UAF.pvl" + '" ' + query_path, stdout=PIPE, stderr=PIPE)
    timer = Timer(20, lambda process: process.kill(), [output])
    try:
        timer.start()
        stdout, stderr = output.communicate()
        return_code = output.returncode
    finally:
        timer.cancel()
    i = stdout[0:-10].rfind(b'--------------------------------------------------------------') # find last results
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
    return ret, result # return the results



def analyze(root_path,content_class,target_scene_class):
    target_scene = target_scene_class()
    if not os.path.exists(root_path + "/" + "RESULT/"):
        os.makedirs(root_path + "/" + "RESULT/")
    if not os.path.exists(root_path + "/" + "TEMP/"):
        os.makedirs(root_path + "/" + "TEMP/")
    if not os.path.exists(root_path + "/" + "LOG/"):
        os.makedirs(root_path + "/" + "LOG/")
    gen = Generator(content_class,target_scene)
    jump = Jump()
    log_file = open(root_path + "/LOG/" + target_scene.scene_name + ".log","w")
    count = 0
    while True:
        state, gen_content = gen.generate_case()
        if state == -1:#finish
            break
        elif state == 1:#reset counter when query new
            count = 0
        log_msg = str(count).ljust(6)
        if jump.is_secure(gen_content):
            log_msg += "  skipping"
            log_msg += " TYPE "
            log_msg += gen_content.scene_name.ljust(6)
            log_msg += " QUERY "
            log_msg += gen_content.query_name.ljust(4)
            log_msg += " LEAK "
            log_msg += gen_content.leak_lines_write.ljust(5)
            log_msg += " MALICIOUS "
            log_msg += gen_content.malicious_lines_write.ljust(8)
            log_msg += " TIME "
            log_msg += time.strftime('%Y.%m.%d %H:%M ', time.localtime(time.time()))
        else:
            content = gen_content.get_content()
            temp_pvfile_path = root_path + "/TEMP/" + target_scene.scene_name + "temp.pv"
            f = open(temp_pvfile_path,"w")
            f.writelines(content)
            f.close()
            ret, result = proverif(root_path, temp_pvfile_path)
            if ret == 'true':
                jump.add_secure_scene(gen_content)
            log_msg += "  " + str(ret)
            log_msg += " TYPE "
            log_msg += gen_content.scene_name.ljust(6)
            log_msg += " QUERY "
            log_msg += gen_content.query_name.ljust(4)
            log_msg += " LEAK "
            log_msg += gen_content.leak_lines_write.ljust(5)
            log_msg += " MALICIOUS "
            log_msg += gen_content.malicious_lines_write.ljust(8)
            file_log_write = log_msg
            log_msg += " TIME "
            log_msg += time.strftime('%Y.%m.%d %H:%M ', time.localtime(time.time()))
            if ret != 'false' and ret != 'prove':  #  if not false then write the result file
                if not os.path.exists(root_path + "/" + "RESULT/" + gen_content.scene_name + "/" + gen_content.query_name):
                    os.makedirs(root_path + "/" + "RESULT/" + gen_content.scene_name + "/" + gen_content.query_name)
                f = open(root_path + "/" + "RESULT/" + gen_content.scene_name + "/" + gen_content.query_name + "/" + file_log_write, "w")
                f.writelines(content)
                f.writelines(str(result[-1000:-1]))
                f.close()
        count = count + 1
        print(log_msg, file = log_file)
        log_file.flush()
    log_file.close()


def print_help():
    print("usage: [-help] [-h] [-target <target_name>] [-t <target_name>]")
    print("Options and arguments:")
    print("-h/-help  : show help informations.")
    print("-s/-simple :  analyze cases where the fields are not leaked, this argument will reduce the analyzing time but give incomplete results. If don't specify, then analyze all cases.")
    print("-t/-target  : verify a specific phase, if don't specify, then verify all phases. ")
    print("    The candidates arguments are:")
    print("       reg   : to analyze registration process.")
    print("       auth_1b_em   : to analyze authentication process with 1B authenticator to log in.")
    print("       auth_1b_st   : to analyze authentication process with 1B authenticator to step-up authentication.")
    print("       auth_1r_em   : to analyze authentication process with 1R authenticator to log in.")
    print("       auth_1r_st   : to analyze authentication process with 1R authenticator to step-up authentication.")
    print("       auth_2b   : to analyze authentication process with 2B authenticator to step-up authentication.")
    print("       auth_2r   : to analyze authentication process with 2R authenticator to step-up authentication.")

def reg_analyze(root_path):
    analyze(root_path,Reg_content,Reg_1b_seta)
    analyze(root_path, Reg_content, Reg_1b_noa)
    analyze(root_path, Reg_content, Reg_2b_seta)
    analyze(root_path, Reg_content, Reg_2b_noa)
    analyze(root_path, Reg_content, Reg_1r_seta)
    analyze(root_path, Reg_content, Reg_1r_noa)
    analyze(root_path, Reg_content, Reg_2r_seta)
    analyze(root_path, Reg_content, Reg_2r_noa)

def auth_analyze(root_path):
    analyze(root_path, Auth_content, Auth_1b_seta_login)
    analyze(root_path, Auth_content, Auth_1b_seta_stepup)
    analyze(root_path, Auth_content, Auth_1b_noa_login)
    analyze(root_path, Auth_content, Auth_1b_noa_stepup)
    analyze(root_path, Auth_content, Auth_2b_seta)
    analyze(root_path, Auth_content, Auth_2b_noa)
    analyze(root_path, Auth_content, Auth_1r_seta_login)
    analyze(root_path, Auth_content, Auth_1r_seta_stepup)
    analyze(root_path, Auth_content, Auth_1r_noa_login)
    analyze(root_path, Auth_content, Auth_1r_noa_stepup)
    analyze(root_path, Auth_content, Auth_2r_seta)
    analyze(root_path, Auth_content, Auth_2r_noa)


if __name__ == "__main__":
    root_path = os.getcwd() + "/"
    regt = threading.Thread(target=reg_analyze, args=(root_path,))  # create threads for each phase
    autht = threading.Thread(target=auth_analyze, args=(root_path,))
    try:
        options, args = getopt.getopt(sys.argv[1:], "-h-help-t:-target:-s-simple", ["help", "target="])
    except getopt.GetoptError:
        print("wrong option!")
        print_help()
        sys.exit()
    for option, value in options:
        if option in ("-h", "-help", "--help"):
            print_help()
            sys.exit()
        elif option in ("-t", "--t", "--target", "-target"):  # if specific which phase to analyze, then clean the tlist
            tlist = []
    regt.start()
    autht.start()
    regt.join()
    autht.join()