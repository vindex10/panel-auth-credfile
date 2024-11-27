import argparse
import getpass

from panel_auth_credfile.credentials import hash_password


def hash_password_cmd():
    password = getpass.getpass("Enter password: ")
    return print(hash_password(password).decode("utf-8"))


COMMANDS = {
    "hash_password": hash_password_cmd,
}


def parse_args(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", choices=list(COMMANDS))
    parsed = parser.parse_args(args)
    return COMMANDS[parsed.cmd]


def main():
    parse_args()()
