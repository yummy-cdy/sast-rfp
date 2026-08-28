import os
import pickle
import random
import tempfile
import hashlib

password = "hunter2"
secret_key = "static-encryption-key-0001"


def sql_injection(user_input):
    cursor.execute(f"SELECT * FROM admin WHERE id = '{user_input}'")


def path_traversal():
    return open(request.GET['file_name'], 'r')


def os_command_injection(user_input):
    os.system("ls " + user_input)


def code_injection(user_code):
    return eval(user_code)


def weak_hash(data):
    return hashlib.md5(data)


def insecure_random():
    return random.randint(1, 100)


def insecure_deserialization(data):
    return pickle.loads(data)


def empty_exception():
    try:
        do_work()
    except:
        pass


def debug_mode():
    app.run(debug=True)


def permissive_permission(path):
    os.chmod(path, 0o777)


def open_redirect():
    return redirect(request.args.get("next"))


def ssrf():
    return requests.get(request.args.get("url"))
