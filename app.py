import base64
import hmac
import html
import json
import os
import re
import secrets
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode
from urllib.request import Request, urlopen
from wsgiref.simple_server import make_server
from xml.etree.ElementTree import Element, SubElement, tostring

PHONE = re.compile(r"\+[1-9][0-9]{7,14}")
CONFIG = (
    "JOLLEY_TALK_PASSWORD", "TWILIO_ACCOUNT_SID", "TWILIO_API_KEY_SID",
    "TWILIO_API_KEY_SECRET", "TWILIO_NUMBER", "CALLBACK_NUMBER", "ALLOWED_DESTINATIONS",
)
SETTING = {key: os.environ.get(key, "").strip() for key in CONFIG}
DESTINATIONS = sorted({
    number.strip() for number in SETTING["ALLOWED_DESTINATIONS"].split(",")
    if PHONE.fullmatch(number.strip())
    and number.strip() not in {SETTING["TWILIO_NUMBER"], SETTING["CALLBACK_NUMBER"]}
})
READY = (
    all(SETTING.values()) and len(SETTING["JOLLEY_TALK_PASSWORD"]) >= 16
    and re.fullmatch(r"AC[0-9a-fA-F]{32}", SETTING["TWILIO_ACCOUNT_SID"])
    and re.fullmatch(r"SK[0-9a-fA-F]{32}", SETTING["TWILIO_API_KEY_SID"])
    and PHONE.fullmatch(SETTING["TWILIO_NUMBER"])
    and PHONE.fullmatch(SETTING["CALLBACK_NUMBER"])
    and SETTING["TWILIO_NUMBER"] != SETTING["CALLBACK_NUMBER"]
    and DESTINATIONS
)
FORM_TOKEN = secrets.token_urlsafe(32)
next_call_at = 0.0


def request_callback(destination):
    response = Element("Response")
    dial = SubElement(response, "Dial", callerId=SETTING["TWILIO_NUMBER"],
                      timeout="20", timeLimit="240")
    SubElement(dial, "Number").text = destination
    fields = urlencode({
        "To": SETTING["CALLBACK_NUMBER"],
        "From": SETTING["TWILIO_NUMBER"],
        "Timeout": "20",
        "Twiml": tostring(response, encoding="unicode"),
    })
    credentials = (SETTING["TWILIO_API_KEY_SID"] + ":" + SETTING["TWILIO_API_KEY_SECRET"]).encode()
    account = SETTING["TWILIO_ACCOUNT_SID"]
    request = Request(
        f"https://api.twilio.com/2010-04-01/Accounts/{account}/Calls.json",
        data=fields.encode(),
        headers={"Authorization": "Basic " + base64.b64encode(credentials).decode()},
    )
    with urlopen(request, timeout=8) as result:
        return json.load(result)["sid"]


def page(message=""):
    options = "".join(f'<option value="{number}">{number}</option>' for number in DESTINATIONS)
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Jolley Talk</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100svh;display:grid;place-items:center;
background:#111c1b;color:#effaf4;font:1rem/1.5 system-ui,sans-serif;padding:1.25rem}}
main{{width:min(100%,26rem);padding:2rem;border:1px solid #406058;border-radius:1.25rem;
background:#1b2b29}}h1{{font-size:2.6rem;letter-spacing:-.05em;margin:0}}p{{color:#c3d8d0}}
label,select,button{{display:block;width:100%;font:inherit}}label{{margin-top:1.5rem}}
select,button{{margin-top:.55rem;border-radius:.55rem;padding:.75rem}}select{{background:#121e1c;
color:#effaf4;border:1px solid #69837a}}button{{background:#b9f9cb;color:#102018;
border:0;font-weight:750;cursor:pointer}}button:focus-visible,select:focus-visible{{outline:3px solid white;outline-offset:3px}}
</style>
<main><h1>Jolley Talk</h1><p>We ring your phone first. Answer to connect to your selected number.</p>
<form method="post" action="/call">
<input type="hidden" name="token" value="{FORM_TOKEN}">
<label for="destination">Destination</label>
<select id="destination" name="destination" required>{options}</select>
<button>Start callback</button>
</form><p role="status">{html.escape(message)}</p></main></html>"""


def app(environ, start_response):
    global next_call_at

    def send(status, body, content_type="text/plain", headers=()):
        start_response(status, [
            ("Content-Type", f"{content_type}; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            *headers,
        ])
        return [body.encode()]

    path, method = environ["PATH_INFO"], environ["REQUEST_METHOD"]
    if path == "/health" and method == "GET":
        return send("200 OK", "OK")
    if not READY:
        return send("503 Service Unavailable", "Jolley Talk needs configuration in Render.")
    expected = base64.b64encode(("jolley:" + SETTING["JOLLEY_TALK_PASSWORD"]).encode())
    provided = environ.get("HTTP_AUTHORIZATION", "").encode()
    if not hmac.compare_digest(provided, b"Basic " + expected):
        return send("401 Unauthorized", "Sign in to Jolley Talk.",
                    headers=[("WWW-Authenticate", 'Basic realm="Jolley Talk"')])
    if path == "/" and method == "GET":
        message = "Callback requested. Answer your phone to connect." if environ["QUERY_STRING"] == "sent=1" else ""
        return send("200 OK", page(message), "text/html")
    if path != "/call" or method != "POST":
        return send("404 Not Found", "Page unavailable.")
    length = environ.get("CONTENT_LENGTH", "")
    if not re.fullmatch(r"[0-9]{1,4}", length) or not 0 < int(length) <= 1024:
        return send("400 Bad Request", "Invalid form.")
    try:
        fields = parse_qs(environ["wsgi.input"].read(int(length)).decode("utf-8"), max_num_fields=2)
    except ValueError:
        return send("400 Bad Request", "Invalid form.")
    token = fields.get("token", [""])[0].encode()
    destination = fields.get("destination", [""])[0]
    if not hmac.compare_digest(token, FORM_TOKEN.encode()) or destination not in DESTINATIONS:
        return send("403 Forbidden", "This call is unavailable.")
    if time.monotonic() < next_call_at:
        return send("429 Too Many Requests", page("Wait 30 seconds between call attempts."), "text/html")
    next_call_at = time.monotonic() + 30
    try:
        request_callback(destination)
    except HTTPError as error:
        try:
            code = int(json.load(error)["code"])
        except (ValueError, KeyError, TypeError):
            code = error.code
        return send("502 Bad Gateway", page(f"Twilio rejected the call. Check Twilio error {code}."), "text/html")
    except (URLError, TimeoutError, ValueError, KeyError):
        return send("502 Bad Gateway", page("Twilio did not confirm the request. Check your Voice logs before retrying."), "text/html")
    return send("303 See Other", "", headers=[("Location", "/?sent=1")])


if __name__ == "__main__":
    with make_server("0.0.0.0", int(os.environ.get("PORT", "8000")), app) as server:
        server.serve_forever()
