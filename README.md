# UAFVerif - A formal verification tool to analyze the FIDO UAF protocol
This is the source code repo for UAFVerif, a formal verification tool to analyze the FIDO UAF protocol. This instruction describes the organization of the source code and how to use it.
The results generated by this tool was published in the paper titled "A formal analysis of the FIDO UAF protocol" in The Network and Distributed System Security Symposium 2021 (NDSS). 
If you want to cite our paper in your work, please use the following BibTeX entry.

```
@inproceedings{UAFanalysis2021,
  title={A formal analysis of the FIDO UAF protocol},
  author={Feng, Haonan and Li, Hui and Pan, Xuesong Pan and Zhao, Ziming},
  booktitle={Proceedings of the Network and Distributed System Security Symposium (NDSS)},
  pages={x--x},
  year={2021},
}
```

## Instructions

To run UAFVerif, you need ProVerif 2.01+ and Python 3.0+.

### Requirements
1. [ProVerif 2.01](https://prosecco.gforge.inria.fr/personal/bblanche/proverif/): download the ProVerif.exe, and add the ProVerif.exe into the SYSTEM PATH.
2. Python 3.0+: to batch ProVerif input file

### File Organization

Source code files:

- UAFVerif.pv: a python script to analyze the UAF protocol in batches and output the results.
- FIDO.pvl: a lib file that contains all operations of the UAF protocol.
- reg.pv: registration process to analyze confidentiality and authentication goals.
- reg_unlink.pv: registration process to analyze unlinkability goals.
- auth.pv: authentication process to analyze confidentiality and authentication goals.
- auth_unlink.pv: authentication process to analyze unlinkability goals.

Generated files:

- LOG/xxx.log: a log file to record all analysis.
- result/: a directory to store all analysis results.
- TEMP/TEMP--xxxxxxx.pv: a temporary file generated by the UAFVerif.pv for ProVerif to analyze a specific case.

### Using Guidelines

#### Verify the confidentiality and authentication goals

With a large number of input cases, we use a python script to batch analyze, the script is in directory "script".
You can run the script without arguments and analyze confidentiality and authentication objectives in all cases.

```
../FIDO-UAF-Verification> python script/script.py
```

Or you can run the script with -t/-target to specific which process you want to analyze.
- "reg" represents the registration process.
- "auth_1b_em" represents the authentication process for 1B authentication in login phase.
- "auth_1b_st" represents the authentication process for 1B authentication in step-up authentication phase.
- "auth_1r_em" represents the authentication process for 1R authentication in login phase.
- "auth_1r_st" represents the authentication process for 1R authentication in step-up authentication phase.
- "auth_2b" represents the authentication process for 2B authentication in step-up authentication phase.
- "auth_2r" represents the authentication process for 2R authentication in step-up authentication phase.

```
../FIDO-UAF-Verification> python script/script.py -t reg 
../FIDO-UAF-Verification> python script/script.py -t auth_1b_em 
../FIDO-UAF-Verification> python script/script.py -t auth_1b_st 
../FIDO-UAF-Verification> python script/script.py -t auth_1r_em 
../FIDO-UAF-Verification> python script/script.py -t auth_1r_st 
../FIDO-UAF-Verification> python script/script.py -t auth_2b 
../FIDO-UAF-Verification> python script/script.py -t auth_2r 
```

After running the script, you can find the result in result folder.
The results are classified by folder, for example, "../result/reg/autr_1b/S-ak" contains the result of the confidentiality of the *ak* in registration process, 1B authenticator scene.
Then the files shows the minimal assumptions of this result, for example "34   reg   true type autr_1b query S-ak fields-1  mali-6 ,0,1,2,3,4,7" means we firstly found a minimal assumptions, where one data field can be compromised and 6 malicious entities can exist.
Opennig the file, you can find which fields can be compromised and which malicious entities are exist to let the protocol satisifies the security goal.

Also, there would be the log files which record all the analysis procedure.

#### Verify the unlinkability goals

Go to the rootpath, and run following command.

```
../FIDO-UAF-Verification> proverif -lib "FIDO.pvl" reg_unlink.pv" or "proverif -lib "FIDO.pvl" reg_unlink.pv
../FIDO-UAF-Verification> proverif -lib "FIDO.pvl" reg_unlink.pv" or "proverif -lib "FIDO.pvl" auth_unlink.pv
```

To analyze unlinkability for different type authenticator, set the "atype" and "scene" in .pv file.


	
