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
