"""Bounded local lab authorization checks; response bodies/cookies are not saved."""
import json
import http.cookiejar
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

BASE = "http://127.0.0.1:5000"
OUT = Path(__file__).resolve().parents[1] / "reports/tt-assessment/runtime.json"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def client():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())

def get(c, path, data=None, headers=None):
    request = urllib.request.Request(BASE+path,
        data=urllib.parse.urlencode(data).encode() if data is not None else None,
        headers=headers or {})
    try:
        response = c.open(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read(65536)

def object_body(body):
    try: return json.loads(body)
    except (ValueError, UnicodeError): return None

def main():
    checks = []
    guest = client()
    code, _, body = get(guest, "/")
    if code != 200 or b"VulnShop" not in body:
        raise RuntimeError("Local service does not match VulnShop; stopped")
    alice, bob = client(), client()
    for c, name in ((alice, "alice"), (bob, "bob")):
        status, _, _ = get(c, "/login", {"username": name, "password": name+"123"})
        if status != 302:
            raise RuntimeError("Fixture login unsuccessful; stopped")
    status_b, _, b = get(bob, "/orders/101")
    status_a, _, a = get(alice, "/orders/101")
    status_g, _, _ = get(guest, "/orders/101")
    ob, oa = object_body(b), object_body(a)
    confirmed = (status_a == status_b == 200 and isinstance(ob,dict)
        and ob.get("id") == 101 and ob.get("user_id") == 2 and oa == ob
        and status_g in (302,401,403))
    checks.append({"check":"horizontal_order_access","path":"/orders/101",
        "confirmed":confirmed,"alice_status":status_a,"bob_status":status_b,
        "guest_status":status_g,"owner_control_valid":isinstance(ob,dict) and ob.get("user_id")==2})
    bstatus, _, b = get(bob, "/profile/2")
    astatus, _, a = get(alice, "/profile/2")
    ob = object_body(b)
    checks.append({"check":"horizontal_profile_access","path":"/profile/2",
        "confirmed":astatus==bstatus==200 and isinstance(ob,dict) and ob.get("id")==2 and object_body(a)==ob})
    status, _, body = get(guest, "/admin")
    data = object_body(body)
    checks.append({"check":"unauthenticated_admin_access","path":"/admin",
        "confirmed":status==200 and isinstance(data,list) and any(isinstance(u,dict) and u.get("role")=="admin" for u in data),
        "status":status})
    status, headers, _ = get(guest, "/", headers={"Origin":"https://scanner-test.invalid"})
    checks.append({"check":"cors_origin_reflection","path":"/",
        "confirmed":headers.get("Access-Control-Allow-Origin")=="https://scanner-test.invalid"
            and headers.get("Access-Control-Allow-Credentials")=="true",
        "note":"Header behavior verified; browser exploitability depends on cookie and request context."})
    OUT.write_text(json.dumps({"target":BASE,"status":"completed",
        "method":"Focused custom HTTP checks, not the generic IDOR adapter",
        "checks":checks,"not_tested":["command injection execution","file upload","stored XSS writes",
        "debug environment disclosure","rate-limit load testing"]},indent=2),encoding="utf-8")
    print(json.dumps(checks,indent=2))

if __name__ == "__main__":
    try: main()
    except (OSError,RuntimeError) as error:
        OUT.write_text(json.dumps({"target":BASE,"status":"blocked","reason":str(error)},indent=2),encoding="utf-8")
        print(type(error).__name__,str(error))

