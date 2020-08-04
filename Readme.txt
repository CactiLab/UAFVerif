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

	