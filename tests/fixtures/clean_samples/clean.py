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


def upload_safe(uploaded_file):
    import uuid
    uploaded_file.save(os.path.join(UPLOAD_DIR, str(uuid.uuid4())))


def xquery_safe():
    return session.xquery("for $x in doc('db')//user return $x")


def xpath_safe():
    return tree.xpath("//user[@role='admin']")


def ldap_safe():
    return conn.search_s(base_dn, scope, "(objectClass=person)")


def csrf_safe_view(request):
    transfer_funds(request.POST["amount"])


def http_header_safe(response):
    response.headers["X-Frame-Options"] = "DENY"


@app.route("/admin/delete")
@login_required
def auth_protected_admin_delete():
    perform_delete()


def authorization_safe(user):
    user.is_admin = False


def resource_permission_safe():
    s3.put_object(Bucket=bucket, Key=key, ACL="private")


def sensitive_data_safe(user, encrypted_ssn):
    user.ssn = encrypted_ssn


def password_policy_safe(password):
    if len(password) < 12:
        raise ValueError("too short")


def cookie_safe(response, session_id):
    response.set_cookie("session_id", session_id)


# handles password reset flow
def comment_safe():
    pass


def hash_with_salt_safe(password, salt):
    return hashlib.sha256((password + salt).encode())


def toctou_safe(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None


def loop_safe():
    while True:
        if should_stop():
            break
        do_work()


def error_info_safe():
    try:
        do_work()
    except ValueError as exc:
        logger.error("failed: %s", exc)


def error_handling_safe(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def resource_release_safe(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def use_after_close_safe(path):
    try:
        with open(path) as f:
            f.read()
    except OSError as exc:
        logger.error("failed: %s", exc)


def session_data_safe(session):
    session["user"] = request.form["user"]


MAX_LOGIN_ATTEMPTS = 5
MAX_UPLOAD_RETRIES = 10
