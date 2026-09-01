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


def dangerous_file_upload(uploaded_file):
    uploaded_file.save(os.path.join(UPLOAD_DIR, uploaded_file.filename))


def xquery_injection(name):
    return session.xquery(f"for $x in doc('db')//user[name='{name}'] return $x")


def xpath_injection(name):
    return tree.xpath("//user[@name='" + name + "']")


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
