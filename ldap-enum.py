from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, Tls
from pathlib import Path
from ldap3 import BASE
import ssl
from tabulate import tabulate

USE_SSL=True
AUTO_RESOLVE_DOMAIN=False
IP_LIST="ldap.txt"
DOMAIN=""
USER=""
PASSWORD=""

headers = ["User", "Groups", "UAC"]


FLAGS = [
    (0x00000002, "ACCOUNTDISABLE"),
    (0x00000008, "HOMEDIR_REQUIRED"),
    (0x00000010, "LOCKOUT"),
    (0x00000020, "PASSWORD_NOT_REQUIRED"),
    (0x00000040, "PASSWORD_CANT_CHANGE"),   # not directly stored in uac; usually via ACL
    (0x00000080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
    (0x00000100, "TEMP_DUPLICATE_ACCOUNT"),
    (0x00000200, "NORMAL_ACCOUNT"),
    (0x00000800, "INTERDOMAIN_TRUST_ACCOUNT"),
    (0x00001000, "WORKSTATION_TRUST_ACCOUNT"),
    (0x00002000, "SERVER_TRUST_ACCOUNT"),
    (0x00010000, "DONT_EXPIRE_PASSWORD"),
    (0x00020000, "MNS_LOGON_ACCOUNT"),
    (0x00040000, "SMARTCARD_REQUIRED"),
    (0x00080000, "TRUSTED_FOR_DELEGATION"),
    (0x00100000, "NOT_DELEGATED"),
    (0x00200000, "USE_DES_KEY_ONLY"),
    (0x00400000, "DONT_REQUIRE_PREAUTH"),
    (0x00800000, "PASSWORD_EXPIRED"),
    (0x01000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
]

def decode_uac(uac):
    if isinstance(uac, list):
        uac = int(uac[0])
    else:
        uac = int(uac)
    flags = [name for bit, name in FLAGS if (uac & bit) == bit]
    return " | ".join(flags) if flags else "NONE"

def decode_instance_type(value):
    flags = []
    if isinstance(value, list):
        value = int(value[0])
    else:
        value = int(value)
    if value & 0x01:
        flags.append("OBJECT_IS_MASTER")
    if value & 0x02:
        flags.append("OBJECT_REPLICABLE")
    if value & 0x04:
        flags.append("OBJECT_WRITEABLE")

    return "|".join(flags) if flags else "NONE"


def decode_groups(attrs):
    if 'memberOf' in attrs:
        

def ldap_search(conn, base_domain, query, attributes=None):



    users_list = []
    for entry in conn.extend.standard.paged_search(
                                                    search_base=base_domain,
                                                    search_filter=query,
                                                    search_scope=SUBTREE,
                                                    attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES] if not attributes else attributes,
                                                    paged_size=1000,
                                                    generator=True):
        if entry.get('type') == 'searchResEntry':
            dn = entry.get('dn')
            attrs = entry.get('attributes', {})

            
            if 'objectClass' in attrs and 'user' in attrs['objectClass']:
                sam_account_name = attrs['sAMAccountName']
                groups = decode_groups(attrs)
                uac = decode_uac(attrs['userAccountControl'])

                new_value = []
                users_list.append(new_value)
                

            """
            for k, v in attrs.items():
                if k=="userAccountControl":
                    new_entry["attrs"].append({"id": k, "val": decode_uac(v)})entry
                elif k=="instanceType":

                    new_entry["attrs"].append({"id": k, "val": decode_instance_type(v)})
                else:    
                    new_entry["attrs"].append({"id": k, "val": v})
            """
    
    print(tabulate(users_list, headers=headers,tablefmt="github"))
tls_config =Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)


ip = "10.209.5.14"
if not USE_SSL:
    server = Server(f"ldap://{ip}", get_info=ALL)
else:
    server = Server(f"ldaps://{ip}", port=636, use_ssl=True, get_info=ALL, tls=tls_config)

conn = Connection(server, user=USER, password=PASSWORD, auto_bind=True)

if AUTO_RESOLVE_DOMAIN:
    print("[*] Resolving base domain via RootDSE...")
    conn.search(search_base='', search_filter='(objectClass=*)', search_scope=BASE)
    if conn.entries:
        root_dse_entry = conn.response[0]
        base_domain = root_dse_entry['attributes'].get('defaultNamingContext')
        print(f"[+] Base domain resolved: {base_domain}")
    else:
        print("[-] Could not resolve base domain automatically.")
        sys.exit(1)
else:
    base_domain=DOMAIN.replace(".",",DC=")
    base_domain="DC="+base_domain

print("[*] Getting users info...")
users_full = ldap_search(conn, base_domain, '(sAMAccountName=*)')



