import sys
from pathlib import Path
import os

SHARE_LIST_FILE = "subnet.txt"
PATH_LIST = ["SYSVOL", "NETLOGON"]
USER = ""
PWD = ""
EXT_LIST = ["bat","cmd","vbs","txt"]

start_dir = os.getcwd()
print(f"Start directory: {start_dir}")
share_f = open(SHARE_LIST_FILE, 'r')
for ip in share_f.readlines():
    ip = ip.strip("\n")
    new_directory = f"smb_share/{ip}"
    Path(new_directory).mkdir(parents=True, exist_ok=True)
    print(f"Changing diectory to {new_directory}")
    os.chdir(new_directory)
    for path in PATH_LIST:
        for ext in EXT_LIST:
            cmd = f"smbclient //{ip}/{path} -U '{USER}%{PWD}' -c \"prompt off; mask *.{ext}; recurse on; mget *\""
            #print(cmd)
            os.system(cmd)
    os.chdir(start_dir)


    
share_f.close()
