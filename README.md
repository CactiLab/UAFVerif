# FIDO UAF verification source code repository
This README describes the organization of the source code of the FIDO UAF verification and describes how to use this code to verify the UAF protocol.
This project is a part of work of the paper "A formal analysis of the FIDO UAF protocol", which was published in The Network and Distributed System Security Symposium 2021 (NDSS 2021).

## Instructions

### Requirements

1. ProVerif2.01 (you need to add the ProVerif.exe into the SYSTEM PATH)
2. Python3.0+ (to batch ProVerif input file)

### File Organization

- script/script.pv : a python script to analyze the UAF protocol in batches and output the results.
- FIDO.pvl : a lib file which contains all operations of the UAF protocol.
- reg.pv : registration process to analyze confidentiality and authentication goals.
- reg_unlink.pv : registration process to analyze unlinkability goals.
- auth.pv : authentication process to analyze confidentiality and authentication goals.
- auth_unlink.pv : authentication process to analyze unlinkability goals.


Requirements:
	1. Windows
	2. ProVerif2.01: you need to add the ProVerif.exe into the SYSTEM PATH.
	3. Python


Verify the confidentiality and authentication goals:

	By running the "script.py", you can automate analyze the Confidentiality and the authentication goals for UAF protocol for all scenes.

	1. First, you should set the value of "rootpath" in class "Setting", the path is where the Reg.pv and FIDO.pvl files exist.
	2 run "script.py" in scripy folder.
	3 find results in the "result" folder.
	4 You can add additional scenarios or queries that you want to verify. Refer to code comments for details.
	
	
	
Verify the unlinkability goals:
	1. go to the rootpath
	2. run "proverif -lib "FIDO.pvl" reg_unlink.pv" or "proverif -lib "FIDO.pvl" auth_unlink.pv"
	3. to analyze unlinkability for different type authenticator, set the "atype" and "scene" in .pv file.

	