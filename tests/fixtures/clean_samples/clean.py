import hashlib
import secrets
import json
import subprocess


def sql_safe(user_input, cursor):
    cursor.execute("SELECT * FROM admin WHERE id = %s", (user_input,))


def hash_safe(data):
    return hashlib.sha256(data)


def random_safe():
    return secrets.token_hex(16)


def deserialize_safe(data):
    return json.loads(data)


def exception_safe():
    try:
        do_work()
    except ValueError as exc:
        logger.error("failed: %s", exc)


def command_safe(args):
    subprocess.run(["ls", args], shell=False)
