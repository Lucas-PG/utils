"""
Script to list users with expired passwords in Active Directory.
"""

import json
from datetime import datetime, timedelta

from dotenv import dotenv_values, load_dotenv
from ldap3 import ALL, Connection, Server
from tabulate import tabulate

load_dotenv()
config = dotenv_values()
pso_max_ages = {}
expired_users = {}


def get_users(conn):
    user_filter = (
        "(&(objectCategory=Person)(objectclass=User)(objectClass=inetOrgPerson))"
    )
    user_attributes = ["uid", "msDS-ResultantPSO", "pwdLastSet"]
    conn.search(
        config["USER_BASE_DN"], search_filter=user_filter, attributes=user_attributes
    )
    if conn.entries:
        return conn.entries
    return False


def check_pwd_expiry(user, conn):
    uid = str(user["uid"])
    pso = str(user["msDS-ResultantPSO"]).split(",")[0]
    pwd_last_set = str(user["pwdLastSet"]).split(".")[0]

    if not pso_max_ages.get(pso):
        conn.search(
            config["BASE_DN"],
            search_filter=f"({pso})",
            attributes="msDS-MaximumPasswordAge",
        )
        pso_max_ages[pso] = str(conn.entries[0]["msDS-MaximumPasswordAge"])

    user_max_pwd_age = pso_max_ages.get(pso)
    if user_max_pwd_age:
        pwd_age_days = (int(str(user_max_pwd_age))) / -864000000000
    else:
        print(f"Falha ao encontrar o PSO do usuário {uid}")
        return

    pwd_last_set_date = datetime.strptime(pwd_last_set, "%Y-%m-%d %H:%M:%S")
    pwd_expires = pwd_last_set_date + timedelta(
        days=pwd_age_days
    )  # Data de expiração da senha

    expired = pwd_expires <= datetime.now()
    pwd_expires_formatted = pwd_expires.strftime("%d/%m/%Y")

    if expired:
        expired_users[uid] = {"uid": uid, "pwdExpires": pwd_expires_formatted}


if __name__ == "__main__":
    try:
        server = Server(config["AD_SERVER"], get_info=ALL)
        conn = Connection(
            server=server,
            user=config["BIND_DN"],
            password=config["BIND_PASS"],
            auto_bind=True,
        )
        conn.start_tls()

        users = get_users(conn)
        if users:
            for user in users:
                check_pwd_expiry(user, conn)

            sorted_dict = dict(sorted(expired_users.items()))

            table_data = [
                [uid, value["pwdExpires"]] for uid, value in sorted_dict.items()
            ]

            print(
                tabulate(
                    table_data, headers=["UID", "Expiration Date"], tablefmt="grid"
                )
            )

            print(f"\nNúmero de usuários: {len(expired_users)}")
        else:
            print("Não foi possível buscar usuários no AD")
    except Exception as e:
        print(e)
