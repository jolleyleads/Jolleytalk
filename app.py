import base64
import hashlib
import hmac
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

PHONE = re.compile(r"\+1[2-9][0-9]{2}[2-9][0-9]{6}")
PASSWORD = os.getenv("JOLLEY_TALK_PASSWORD", "")
NUMBER = os.getenv("TWILIO_NUMBER", "")
ACCOUNT = os.getenv("TWILIO_ACCOUNT_SID", "")
VOICE_KEY = os.getenv("TWILIO_VOICE_KEY_SID", "")
VOICE_SECRET = os.getenv("TWILIO_VOICE_KEY_SECRET", "")
VOICE_APP = os.getenv("TWILIO_VOICE_APP_SID", "")
SMS_KEY = os.getenv("TWILIO_SMS_KEY_SID", "")
SMS_SECRET = os.getenv("TWILIO_SMS_KEY_SECRET", "")
ALLOWLIST = {n.strip() for n in os.getenv("ALLOWED_DESTINATIONS", "").split(",") if n.strip()}
VOICE_READY = bool(PHONE.fullmatch(NUMBER) and re.fullmatch(r"AC[0-9a-fA-F]{32}", ACCOUNT)
                   and re.fullmatch(r"SK[0-9a-fA-F]{32}", VOICE_KEY) and VOICE_SECRET
                   and re.fullmatch(r"AP[0-9a-fA-F]{32}", VOICE_APP))
SMS_READY = bool(PHONE.fullmatch(NUMBER) and re.fullmatch(r"AC[0-9a-fA-F]{32}", ACCOUNT)
                 and re.fullmatch(r"SK[0-9a-fA-F]{32}", SMS_KEY) and SMS_SECRET)
CSRF = secrets.token_urlsafe(32)
used_tickets = {}
last_request = {}


def destination_allowed(number):
    return bool(PHONE.fullmatch(number) and number != NUMBER and
                (not ALLOWLIST or number in ALLOWLIST))


def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def sign(data):
    return b64(hmac.digest(VOICE_SECRET.encode(), data.encode(), hashlib.sha256))


def voice_credentials(number):
    now = int(time.time())
    header = {"typ": "JWT", "alg": "HS256", "cty": "twilio-fpa;v=1"}
    payload = {
        "jti": f"{VOICE_KEY}-{now}-{secrets.token_hex(8)}", "iss": VOICE_KEY,
        "sub": ACCOUNT, "iat": now, "nbf": now, "exp": now + 300,
        "grants": {"identity": "jolley", "voice": {"outgoing": {"application_sid": VOICE_APP}}},
    }
    jwt = ".".join(b64(json.dumps(item).encode()) for item in (header, payload))
    ticket = f"{number}.{now + 90}.{secrets.token_urlsafe(16)}"
    return {"token": f"{jwt}.{sign(jwt)}", "ticket": f"{ticket}.{sign(ticket)}"}


def dial_instructions(ticket, now):
    response = Element("Response")
    parts = ticket.split(".")
    if VOICE_READY and len(parts) == 4:
        number, expiry, nonce, signature = parts
        if (destination_allowed(number) and expiry.isascii() and expiry.isdecimal()
                and now <= int(expiry) <= now + 90 and nonce not in used_tickets
                and hmac.compare_digest(signature.encode(), sign(".".join(parts[:3])).encode())):
            used_tickets[nonce] = int(expiry)
            dial = SubElement(response, "Dial", callerId=NUMBER, timeout="25", timeLimit="300")
            SubElement(dial, "Number").text = number
            return tostring(response, encoding="unicode")
    SubElement(response, "Hangup")
    return tostring(response, encoding="unicode")


def twilio_messages(fields=None):
    credentials = base64.b64encode(f"{SMS_KEY}:{SMS_SECRET}".encode()).decode()
    url = f"https://api.twilio.com/2010-04-01/Accounts/{ACCOUNT}/Messages.json"
    data = urlencode(fields).encode() if fields else None
    request = Request(url if data else url + "?PageSize=50", data=data,
                      headers={"Authorization": f"Basic {credentials}"})
    with urlopen(request, timeout=8) as result:
        return json.load(result)


def get_fields(environ, limit):
    length = environ.get("CONTENT_LENGTH", "")
    if not re.fullmatch(r"[0-9]{1,5}", length) or not 0 < int(length) <= limit:
        raise ValueError("Invalid request size")
    return environ["wsgi.input"].read(int(length)).decode("utf-8")


def app(environ, start_response):
    def send(status, body, content_type="text/plain", headers=()):
        start_response(status, [
            ("Content-Type", f"{content_type}; charset=utf-8"),
            ("Cache-Control", "no-store"), ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
            *headers,
        ])
        return [body.encode()]

    def respond(status, data):
        return send(status, json.dumps(data), "application/json")

    path, method = environ["PATH_INFO"], environ["REQUEST_METHOD"]
    if path == "/health" and method == "GET":
        return send("200 OK", "OK")
    if path == "/voice/outbound" and method == "POST":
        try:
            fields = parse_qs(get_fields(environ, 8192), max_num_fields=60)
        except ValueError:
            return send("400 Bad Request", "Invalid request")
        now = int(time.time())
        for nonce, expiry in list(used_tickets.items()):
            if expiry < now:
                del used_tickets[nonce]
        return send("200 OK", dial_instructions(fields.get("Ticket", [""])[0], now), "text/xml")

    if len(PASSWORD) < 16:
        return send("503 Service Unavailable", "Set JOLLEY_TALK_PASSWORD in Render.")
    expected = base64.b64encode(f"jolley:{PASSWORD}".encode())
    if not hmac.compare_digest(environ.get("HTTP_AUTHORIZATION", "").encode(), b"Basic " + expected):
        return send("401 Unauthorized", "Sign in to Jolley Talk.",
                    headers=[("WWW-Authenticate", 'Basic realm="Jolley Talk"')])
    if path == "/" and method == "GET":
        settings = json.dumps({"number": NUMBER if PHONE.fullmatch(NUMBER) else "",
                               "voice": VOICE_READY, "sms": SMS_READY, "csrf": CSRF})
        return send("200 OK", PAGE.replace("__APP_CONFIG__", settings), "text/html")
    if path == "/api/messages" and method == "GET" and SMS_READY:
        try:
            messages = twilio_messages().get("messages", [])
        except (URLError, TimeoutError, ValueError):
            return respond("502 Bad Gateway", {"error": "Couldn’t load messages from the provider."})
        keys = ("sid", "from", "to", "body", "date_created", "status")
        return respond("200 OK", {"messages": [{key: item.get(key) for key in keys}
                        for item in messages if NUMBER in (item.get("from"), item.get("to"))]})
    if method != "POST" or path not in {"/api/voice", "/api/messages"}:
        return respond("404 Not Found", {"error": "Page unavailable."})
    if not hmac.compare_digest(environ.get("HTTP_X_JOLLEY_TOKEN", "").encode(), CSRF.encode()):
        return respond("403 Forbidden", {"error": "Reload the page and try again."})
    try:
        data = json.loads(get_fields(environ, 4096))
        number = data["number"]
        if not isinstance(number, str):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        return respond("400 Bad Request", {"error": "Enter a valid phone number."})
    if not destination_allowed(number):
        return respond("400 Bad Request", {"error": "This number is outside your enabled destinations."})
    if (path == "/api/voice" and not VOICE_READY) or (path == "/api/messages" and not SMS_READY):
        return respond("503 Service Unavailable", {"error": "Provider setup is pending."})
    body = data.get("body", "")
    if path == "/api/messages" and (not isinstance(body, str) or not 0 < len(body.strip()) <= 500):
        return respond("400 Bad Request", {"error": "Enter a message of 1 to 500 characters."})
    now = time.monotonic()
    if now - last_request.get(path, now - 15) < 15:
        return respond("429 Too Many Requests", {"error": "Wait 15 seconds before trying again."})
    last_request[path] = now
    if path == "/api/voice":
        return respond("200 OK", voice_credentials(number))
    try:
        result = twilio_messages({"From": NUMBER, "To": number, "Body": body.strip()})
    except HTTPError as error:
        return respond("502 Bad Gateway", {"error": f"The provider rejected the message (HTTP {error.code})."})
    except (URLError, TimeoutError, ValueError):
        return respond("502 Bad Gateway", {"error": "Delivery is unconfirmed. Check the inbox before retrying."})
    return respond("202 Accepted", {"status": result.get("status", "queued")})


PAGE = r'''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jolley Talk</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f0eef9;color:#211637;font:16px/1.5 system-ui,sans-serif}
main{max-width:480px;min-height:100svh;margin:auto;background:#fff;padding:26px clamp(17px,6vw,34px);box-shadow:0 0 60px #28184912}
header{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:28px}
h1{margin:0;font-size:1.65rem;letter-spacing:-.055em}h2{font-size:1.2rem;margin:22px 0 8px}.line{font-size:.8rem;color:#665a7d;text-align:right}
nav{display:flex;padding:5px;gap:5px;background:#f0edf8;border-radius:14px}button,input,textarea{font:inherit}
button{border:0;border-radius:10px;cursor:pointer;color:inherit}button:focus-visible,input:focus-visible,textarea:focus-visible{outline:3px solid #8954d7;outline-offset:2px}
nav button{flex:1;background:transparent;padding:10px 4px;font-weight:650}nav button[aria-pressed=true]{background:#fff;box-shadow:0 1px 5px #28184922}
.notice{padding:10px 13px;border-radius:10px;background:#f7f1ff;color:#583893;font-size:.9rem}
label{display:block;font-weight:620;margin-bottom:6px}input,textarea{width:100%;padding:12px;border:1px solid #d9d0e8;border-radius:10px;background:#fff;color:inherit}
#dial-number{font-size:1.75rem;text-align:center;padding:9px;letter-spacing:.025em}
.keys{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:16px 0}
.keys button{min-height:58px;background:#f5f1fb;font-size:1.4rem}.keys small{display:block;font-size:.57rem;letter-spacing:.15em;color:#665a7d}
.actions{display:flex;gap:8px}.actions button{flex:1}.primary{background:#6235af;color:#fff;font-weight:720;padding:12px 16px}.secondary{background:#f1edf9;padding:12px 16px}
button:disabled{opacity:.5;cursor:default}textarea{resize:vertical;min-height:80px;margin-bottom:8px}
.status{font-size:.9rem;color:#665a7d;min-height:1.5em}ul{list-style:none;padding:0}li{padding:10px 0;border-bottom:1px solid #ece5f7;overflow-wrap:anywhere}li small{display:block;color:#665a7d}
</style>
<main><header><h1>Jolley Talk</h1><div class="line">My number<br><strong id="line">Unassigned</strong></div></header>
<nav aria-label="Jolley Talk"><button data-panel="dial" aria-pressed="true">Calls</button><button data-panel="inbox" aria-pressed="false">Messages</button><button data-panel="recent" aria-pressed="false">Recents</button></nav>
<section id="dial"><h2>Dial pad</h2><p id="voice-setup" class="notice" hidden>Calling is waiting for a voice provider connection.</p>
<label for="dial-number">Phone number</label><input id="dial-number" type="tel" autocomplete="off" placeholder="(555) 000-0000">
<div class="keys" id="keys" aria-label="Dial pad"></div><div class="actions"><button id="erase" class="secondary">Delete</button><button id="call" class="primary">Call</button><button id="hangup" class="secondary" hidden>End call</button></div>
<p id="call-status" class="status" role="status"></p></section>
<section id="inbox" hidden><h2>Messages</h2><p id="sms-setup" class="notice" hidden>Messages are waiting for a messaging provider connection.</p>
<form id="sms"><label for="sms-number">To</label><input id="sms-number" type="tel" required><label for="sms-body">Message</label><textarea id="sms-body" required maxlength="500"></textarea>
<button id="send" class="primary">Send</button> <button id="refresh" class="secondary" type="button">Refresh inbox</button></form><p id="sms-status" class="status" role="status"></p><ul id="messages"></ul></section>
<section id="recent" hidden><h2>Recent calls</h2><p id="no-recent">No calls from this browser yet.</p><ul id="history"></ul></section>
</main>
<script>
const config = __APP_CONFIG__;
const get = id => document.getElementById(id);
get('line').textContent = config.number || 'Unassigned';
get('voice-setup').hidden = config.voice;
get('sms-setup').hidden = config.sms;
get('call').disabled = !config.voice;
get('send').disabled = get('refresh').disabled = !config.sms;
const labels = ['', 'ABC', 'DEF', 'GHI', 'JKL', 'MNO', 'PQRS', 'TUV', 'WXYZ', '', '+', ''];
let device;
let currentCall;
const input = get('dial-number');

for (const [i, key] of [...'123456789*0#'].entries()) {
  const button = document.createElement('button');
  button.append(key);
  const sub = document.createElement('small');
  sub.textContent = labels[i];
  button.append(sub);
  button.addEventListener('click', () => {
    if (currentCall?.status() === 'open') currentCall.sendDigits(key);
    else if (/^[0-9]$/.test(key)) input.value += key;
  });
  get('keys').append(button);
}
get('erase').onclick = () => { input.value = input.value.slice(0, -1); };
document.querySelectorAll('nav button').forEach(button => {
  button.onclick = () => {
    for (const item of document.querySelectorAll('nav button')) {
      const selected = item === button;
      item.setAttribute('aria-pressed', selected);
      get(item.dataset.panel).hidden = !selected;
    }
    if (button.dataset.panel === 'inbox' && config.sms) inbox();
    if (button.dataset.panel === 'recent') recent();
  };
});
function phone(value) {
  const digits = value.replace(/\D/g, '');
  return digits.length === 10 ? '+1' + digits : '+' + digits;
}
async function request(path, data) {
  const options = data ? {method:'POST', headers:{'Content-Type':'application/json','X-Jolley-Token':config.csrf}, body:JSON.stringify(data)} : {};
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw Error(result.error || 'Request failed.');
  return result;
}
function log(items, container, render) {
  container.replaceChildren();
  for (const value of items) {
    const item = document.createElement('li');
    const [label, detail] = render(value);
    const small = document.createElement('small');
    small.textContent = detail;
    item.append(label, small);
    container.append(item);
  }
}
function historyItems() {
  try { return JSON.parse(sessionStorage.getItem('jolley-calls') || '[]'); }
  catch { return []; }
}
function recent() {
  const entries = historyItems();
  get('no-recent').hidden = entries.length > 0;
  log(entries, get('history'), e => [e.number, new Date(e.date).toLocaleString()]);
}
function callFinished(text) {
  get('call-status').textContent = text;
  get('call').disabled = false;
  get('hangup').hidden = true;
}
get('call').onclick = async () => {
  get('call').disabled = true;
  const number = phone(input.value);
  get('call-status').textContent = 'Connecting…';
  try {
    if (!navigator.mediaDevices || !window.Twilio?.Device) throw Error('Calling needs microphone access and a supported browser.');
    const {token, ticket} = await request('/api/voice', {number});
    // Request microphone permission before beginning the call.
    const stream = await navigator.mediaDevices.getUserMedia({audio:true});
    stream.getTracks().forEach(track => track.stop());
    device?.destroy();
    device = new Twilio.Device(token);
    const close = text => { currentCall = null; callFinished(text); };
    device.on('error', () => close('The voice provider couldn’t connect the call.'));
    currentCall = await device.connect({params:{Ticket:ticket}});
    get('hangup').hidden = false;
    currentCall.on('ringing', () => { get('call-status').textContent = 'Ringing…'; });
    currentCall.on('accept', () => {
      get('call-status').textContent = 'Connected';
      try { sessionStorage.setItem('jolley-calls', JSON.stringify([{number,date:Date.now()}, ...historyItems()].slice(0,30))); }
      catch {}
    });
    for (const event of ['cancel','disconnect','reject']) currentCall.on(event, () => close('Call ended.'));
    currentCall.on('error', () => close('The voice provider couldn’t complete the call.'));
  } catch (error) { callFinished(error.message); }
};
get('hangup').onclick = () => currentCall?.disconnect();
async function inbox() {
  try {
    const {messages} = await request('/api/messages');
    log(messages, get('messages'), m => [m.body || '', (m.from === config.number ? 'To ' + m.to : 'From ' + m.from) + ' · ' + m.status]);
  } catch (error) { get('sms-status').textContent = error.message; }
}
get('refresh').onclick = inbox;
get('sms').onsubmit = async event => {
  event.preventDefault();
  get('send').disabled = true;
  try {
    const {status} = await request('/api/messages', {number:phone(get('sms-number').value),body:get('sms-body').value});
    get('sms-status').textContent = 'Provider status: ' + status;
    get('sms-body').value = '';
    await inbox();
  } catch (error) { get('sms-status').textContent = error.message; }
  finally { get('send').disabled = false; }
};
if (config.voice) {
  const sdk = document.createElement('script');
  sdk.src = 'https://cdn.jsdelivr.net/npm/@twilio/voice-sdk@2.18.5/dist/twilio.min.js';
  document.head.append(sdk);
}
</script></html>'''

if __name__ == "__main__":
    with make_server("0.0.0.0", int(os.environ.get("PORT", "8000")), app) as server:
        server.serve_forever()
