import sys
from pathlib import Path
from smb.SMBConnection import SMBConnection
from smb.base import NotConnectedError
from tabulate import tabulate
import uuid
import os

SHARE_LIST_FILE = ""
USER = ""
DOMAIN=""
PWD = ""


share_f = open(SHARE_LIST_FILE, 'r')
headers = ["SHARE", "DESCRIPTION"]
for ip in share_f.readlines():
    ip = ip.strip("\n")
    
    

    conn = SMBConnection(USER, PWD, "DATAN", ip,domain=DOMAIN,is_direct_tcp=True, use_ntlm_v2=True)
    
    try:
        if conn.connect(ip, 445, timeout=10):
            shares = conn.listShares()
            print(f"SHARED RESOURCE ON: {ip}")
            print("")
            data = []
            for share in shares:
                data.append([share.name, share.comments]) 
            print(tabulate(data, headers=headers))
            print("")
            conn.close()
    except:
        pass
    

    
    
share_f.close()
