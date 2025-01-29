"""
Script to add otherMailbox attribute to users in AD.
"""

import csv
import re

from dotenv import dotenv_values
from ldap3 import ALL, MODIFY_ADD, MODIFY_REPLACE, Connection, Server

config = dotenv_values()
user_mails = {}


def add_other_mailbox(conn, user, mail):
    user_filter = f"(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(uid={user}))"
    user_attributes = ["cn", "otherMailbox"]
    conn.search(
        config["USER_BASE_DN"], search_filter=user_filter, attributes=user_attributes
    )

    if not conn.entries:
        print(f"AVISO: usuário {user} não encontrado ou desativado.")
        return

    if not conn.entries[0]["cn"]:
        print(f"AVISO: CN não encontrado para usuário: {user}.")
        return

    if not re.search(r"^\S+@\S+\.\S+$", mail):
        print(f"AVISO: E-mail no formato inválido para usuário: {user}")
        return

    if conn.entries[0]["otherMailbox"]:
        operation = MODIFY_REPLACE
    else:
        operation = MODIFY_ADD

    try:
        conn.modify(
            f"cn={str(conn.entries[0]['cn'])},{config['USER_BASE_DN']}",
            {
                "otherMailbox": [(operation, [mail])],
            },
        )
    except Exception as e:
        print(f"AVISO: Erro ao realizar modify para o usuário {user}: ", e)
        return
    print(f"E-mail do usuário {user} cadastrado com sucesso")


if __name__ == "__main__":
    try:
        with open("mails.csv", newline="") as f:
            spamreader = csv.reader(f, delimiter=" ", quotechar="|")
            for row in spamreader:
                for user in row:
                    vals = user.split(",")
                    user_mails[vals[0]] = vals[1]
    except Exception:
        print("Erro ao ler arquivo csv de mails.\n")
        print("Todas as linhas do arquivo devem ter o formato: <uid>,<mail>")
        exit(0)
    try:
        server = Server(config["AD_SERVER"], get_info=ALL)
        conn = Connection(
            server=server,
            user=config["BIND_DN"],
            password=config["BIND_PASS"],
            auto_bind=True,
        )
        conn.start_tls()
    except Exception as e:
        print("Erro ao realizar a se conectar ao AD, ", e)
        exit(0)
    try:
        for user, mail in user_mails.items():
            add_other_mailbox(conn, user, mail)
    except Exception as e:
        print("Erro ao realizar ldapmodify: ", e)
    conn.unbind()
