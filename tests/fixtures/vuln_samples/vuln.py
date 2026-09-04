import os
import pickle
import random
import tempfile
import hashlib

password = "hunter2"
secret_key = "static-encryption-key-0001"


def sql_injection(user_input):
    cursor.execute(f"SELECT * FROM admin WHERE id = '{user_input}'")


def xss(user_input):
    return Markup(user_input)


def path_traversal():
    return open(request.GET['file_name'], 'r')


def os_command_injection(user_input):
    os.system("ls " + user_input)


def os_command_injection_indirect(user_input):
    cmd = "ls " + user_input
    os.system(cmd)


def subprocess_command_injection(user_input):
    import subprocess
    cmd_str = "cmd /c backuplog.bat " + user_input
    subprocess.run(cmd_str, shell=True)


def sql_injection_indirect(user_input):
    query = "SELECT * FROM member WHERE name='" + user_input + "'"
    return Member.objects.raw(query)


def ssrf_urlopen():
    from urllib.request import urlopen
    url = request.GET['url']
    return urlopen(url)


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


def dangerous_file_upload(uploaded_file):
    uploaded_file.save(os.path.join(UPLOAD_DIR, uploaded_file.filename))


def xquery_injection(name):
    return session.xquery(f"for $x in doc('db')//user[name='{name}'] return $x")


def xpath_injection(name):
    return tree.xpath("//user[@name='" + name + "']")


def xpath_injection_indirect(name):
    query = "//user[@name='" + name + "']"
    return tree.xpath(query)


def ldap_injection(username):
    return conn.search_s(base_dn, scope, f"(uid={username})")


@csrf_exempt
def csrf_vulnerable_view(request):
    transfer_funds(request.POST["amount"])


def http_response_splitting(response):
    response.headers["Location"] = request.args.get("next")


@app.route("/admin/delete")
def missing_auth_admin_delete():
    perform_delete()


def improper_authorization(user):
    user.is_admin = request.form.get("is_admin")


def public_resource_permission():
    s3.put_object(Bucket=bucket, Key=key, ACL="public-read")


def unencrypted_sensitive_data(user):
    user.ssn = request.form["ssn"]


def weak_password_policy(password):
    if len(password) < 4:
        raise ValueError("too short")


def sensitive_cookie(response, value):
    response.set_cookie("password", value, max_age=999999)


# password: hunter2
def sensitive_info_in_comment():
    pass


def hash_without_salt(password):
    return hashlib.sha256(password.encode())


def toctou(path):
    if os.path.exists(path):
        f = open(path)
        return f.read()


def infinite_loop():
    while True:
        do_work()


def error_info_exposure():
    try:
        do_work()
    except Exception:
        return traceback.format_exc()


def missing_error_handling(path):
    f = open(path)
    return f.read()


def improper_exception_handling():
    try:
        do_work()
    except Exception as e:
        log(e)


def improper_resource_release(path):
    f = open(path)
    return f.read()


def use_after_close(path):
    f = open(path)
    f.close()
    f.read()


current_request_user = None


def session_data_exposure():
    global current_request_user
    current_request_user = request.form["user"]


MAX_LOGIN_ATTEMPTS = 5
MAX_UPLOAD_RETRIES = 5
