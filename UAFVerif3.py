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
from Content import Reg,Reg_1b_seta, Auth_content


def proverif(root_path,query_path): # activate proverif and analyze the temp.pv file
    output = Popen('proverif -lib "' + root_path + "UAF.pvl" + '" ' + query_path, stdout=PIPE, stderr=PIPE)
    #timer = Timer(20, lambda process: process.kill(), [output])
    try:
        #timer.start()
        stdout, stderr = output.communicate()
        return_code = output.returncode
    finally:
        pass
        #timer.cancel()
    i = stdout[0:-10].rfind(b'--------------------------------------------------------------') # find last results
    result = stdout[i:-1]
    with open(root_path + "LOG/temptestchangehaha.log", "w") as f:
        f.writelines(str(result))
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
    reg_1b_seta = Reg_1b_seta()
    proverif(root_path,reg_1b_seta.get_file_name())
    pass

def auth_analyze(root_path):
    pass

def makedir(root_path):
    if not os.path.exists(root_path + "/" + "RESULT/"):
        os.makedirs(root_path + "/" + "RESULT/")
    if not os.path.exists(root_path + "/" + "TEMP/"):
        os.makedirs(root_path + "/" + "TEMP/")
    if not os.path.exists(root_path + "/" + "LOG/"):
        os.makedirs(root_path + "/" + "LOG/")

def clear_dir(root_path):
    if os.path.exists(root_path + "/" + "RESULT/"):
        shutil.rmtree(root_path + "/RESULT")
    if os.path.exists(root_path + "/" + "TEMP/"):
        shutil.rmtree(root_path + "/TEMP")
    if os.path.exists(root_path + "/" + "LOG/"):
        shutil.rmtree(root_path + "/LOG")

if __name__ == "__main__":
    root_path = os.getcwd() + "/"
    reg_analyze(root_path)
