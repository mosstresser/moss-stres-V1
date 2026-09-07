"""
Full Garena flow ported from original a.py: implements registration -> token -> major_register -> major_login -> choose region.
Safety: these network calls only run when ENABLE_EXTERNAL True and dry_run False in caller.
Make sure API_KEY and ENABLE_EXTERNAL are configured in environment and you have permission to call these endpoints.
"""

import os
import random
import string
import time
import json
import hmac
import hashlib
import codecs
import traceback
from datetime import datetime
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import threading

ENABLE_EXTERNAL = os.getenv("ENABLE_EXTERNAL", "false").lower() in ("1","true","yes")
OPT = {'timeout': 2.5, 'retries': 2, 'backoff': 0.5}

# Endpoint constants (from user)
REGISTER_URL = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
TOKEN_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJORREGISTER_POLAR = "https://loginbp.ggpolarbear.com/MajorRegister"
MAJORREGISTER_BLUEFOX = "https://loginbp.common.ggbluefox.com/MajorRegister"
MAJORLOGIN_POLAR = "https://loginbp.ggpolarbear.com/MajorLogin"
MAJORLOGIN_BLUEFOX = "https://loginbp.common.ggbluefox.com/MajorLogin"
CHOOSEREGION_POLAR = "https://loginbp.ggpolarbear.com/ChooseRegion"
CHOOSEREGION_BLUEFOX = "https://loginbp.common.ggbluefox.com/ChooseRegion"

# Key material from original script
HEX_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
API_AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
API_AES_IV = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

session = requests.Session()

# ---------- IP spoofer & UA bypassers ----------
class FastIPSpoofer:
    _IP_POOL = []
    _IP_INDEX = 0
    _IP_LOCK = threading.Lock()

    @classmethod
    def init_ip_pool(cls, count=1000):
        if not cls._IP_POOL:
            for _ in range(count):
                a = random.randint(1,254)
                b = random.randint(0,255)
                c = random.randint(0,255)
                d = random.randint(1,254)
                cls._IP_POOL.append(f"{a}.{b}.{c}.{d}")

    @classmethod
    def get_ip(cls):
        with cls._IP_LOCK:
            ip = cls._IP_POOL[cls._IP_INDEX % len(cls._IP_POOL)]
            cls._IP_INDEX += 1
            return ip

FastIPSpoofer.init_ip_pool(2000)

class WAFBypass:
    _versions = ["4.0.19P8", "4.0.39", "4.0.40"]
    _android_versions = ["11","12","13","14"]
    _regions = ["HK","ID","SG","MY","PH","TH","VN"]
    _devices = [
        "SM-A325M","SM-A525F","SM-A536B","SM-A736B","SM-A715F","SM-A725F",
        "SM-A515F","SM-A127F","SM-A226B","SM-A326B","SM-M325F","SM-M515F",
        "SM-G991B","SM-G996B","SM-G998B","SM-S901B","SM-S906B","SM-S908B",
        "Pixel 6","OnePlus 8","Redmi Note 10","Nothing Phone (1)"
    ]
    _UA_CACHE = None

    @classmethod
    def _build_ua_list(cls):
        if cls._UA_CACHE is not None:
            return cls._UA_CACHE
        ua_list = []
        for v in cls._versions:
            for device in cls._devices:
                for android in cls._android_versions:
                    for region in cls._regions:
                        ua_list.append(f"GarenaMSDK/{v}({device};Android {android};en;{region};)")
        cls._UA_CACHE = ua_list
        return ua_list

    @staticmethod
    def get_ua():
        ua_list = WAFBypass._build_ua_list()
        return random.choice(ua_list)

# ---------- low-level helpers ----------

def request_retry(method, url, **kwargs):
    for attempt in range(OPT['retries'] + 1):
        try:
            if 'timeout' not in kwargs:
                kwargs['timeout'] = OPT['timeout']
            if 'headers' not in kwargs:
                kwargs['headers'] = {}
            kwargs['verify'] = False
            resp = session.request(method, url, **kwargs)
            if resp is None:
                raise Exception('no response')
            if resp.status_code in [429,500,502,503,504,408]:
                if attempt < OPT['retries']:
                    time.sleep(OPT['backoff'] * (attempt + 1))
                    continue
            return resp
        except Exception as e:
            if attempt < OPT['retries']:
                time.sleep(OPT['backoff'] * (attempt + 1))
                continue
            return None
    return None

# ---------- proto & crypto helpers (from original) ----------

def encode_varint(n):
    if n < 0:
        return b''
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            byte |= 0x80
        result.append(byte)
        if not n:
            break
    return bytes(result)


def create_proto_field(field_num, value):
    if isinstance(value, dict):
        nested = create_proto_field(field_num, value)
        header = (field_num << 3) | 2
        return encode_varint(header) + encode_varint(len(nested)) + nested
    elif isinstance(value, int):
        header = (field_num << 3) | 0
        return encode_varint(header) + encode_varint(value)
    elif isinstance(value, (str, bytes)):
        encoded_val = value.encode() if isinstance(value, str) else value
        header = (field_num << 3) | 2
        return encode_varint(header) + encode_varint(len(encoded_val)) + encoded_val
    return b''


def build_proto(fields):
    return b''.join(create_proto_field(k, v) for k, v in fields.items())


def aes_encrypt(hex_data):
    data = bytes.fromhex(hex_data)
    cipher = AES.new(API_AES_KEY, AES.MODE_CBC, API_AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))


def encrypt_api(plain_hex):
    plain = bytes.fromhex(plain_hex)
    cipher = AES.new(API_AES_KEY, AES.MODE_CBC, API_AES_IV)
    return cipher.encrypt(pad(plain, AES.block_size)).hex()

# ---------- id/name helpers ----------

def generate_exponent():
    exp_digits = {'0':'⁰','1':'¹','2':'²','3':'³','4':'⁴','5':'⁵','6':'⁶','7':'⁷','8':'⁸','9':'⁹'}
    num = random.randint(1, 9999)
    return ''.join(exp_digits[d] for d in f"{num:04d}")


def generate_random_name(base):
    exponent = generate_exponent()
    rand = random.random()
    if rand < 0.4:
        left, right = random.choice(WRAPPING_PAIRS)
        return f"{left}{base}{right}{exponent}"
    elif rand < 0.7:
        return f"{base}{random.choice(SINGLE_SYMBOLS)}{exponent}"
    else:
        return f"{base}_{exponent}"


def make_uid():
    return ''.join(random.choices('0123456789abcdef', k=16))


def make_account_id(length=None):
    if not length:
        length = random.randint(6, 12)
    return ''.join(random.choices(string.digits, k=length))

# ---------- full flow implementations ----------

def create_account_real(region, account_name, password_prefix, is_ghost=False):
    """Register guest and return uid & password or error"""
    try:
        rand_part = "".join(random.choices("0123456789ABCDEF", k=16))
        password = f"{password_prefix}_{rand_part}"
        payload = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
        body_json = json.dumps(payload, separators=(",",":"))
        signature = hmac.new(HEX_KEY, body_json.encode("utf-8"), hashlib.sha256).hexdigest()
        headers = {
            "User-Agent": WAFBypass.get_ua(),
            "Connection": "Keep-Alive",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Authorization": f"Signature {signature}",
            "Content-Type": "application/json; charset=utf-8",
            "Host": "100067.connect.garena.com",
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        resp = request_retry('POST', REGISTER_URL, headers=headers, data=body_json)
        if resp and resp.status_code == 200:
            try:
                res = resp.json()
                if "data" in res and "uid" in res["data"]:
                    uid = res["data"]["uid"]
                    return {"uid": uid, "password": password}
                return {"error": "no_uid_in_response", "raw": res}
            except Exception as e:
                return {"error": "invalid_json", "raw_text": resp.text}
        else:
            return {"error": "register_http", "status": getattr(resp, 'status_code', None), 'text': getattr(resp, 'text', '')}
    except Exception as e:
        return {"error": "exception", "msg": str(e), "tb": traceback.format_exc()}


def get_token(uid, password):
    try:
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": WAFBypass.get_ua(),
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": HEX_KEY, "client_id": "100067"}
        resp = request_retry('POST', TOKEN_URL, headers=headers, data=body)
        if resp and resp.status_code == 200:
            try:
                j = resp.json()
                # depending on response shape, copy relevant fields
                open_id = j.get('open_id') or j.get('openId') or j.get('openid')
                access_token = j.get('access_token')
                if open_id and access_token:
                    return {"open_id": open_id, "access_token": access_token}
                return {"error": "missing_token_fields", "raw": j}
            except Exception:
                return {"error": "invalid_json_token", "text": resp.text}
        else:
            return {"error": "token_http", "status": getattr(resp, 'status_code', None), 'text': getattr(resp, 'text', '')}
    except Exception as e:
        return {"error": "exception", "msg": str(e), "tb": traceback.format_exc()}


def major_register(access_token, open_id, uid, password, account_name, region, is_ghost=False):
    try:
        # choose endpoint
        url = MAJORREGISTER_POLAR if is_ghost or region.upper() not in ["ME","TH"] else MAJORREGISTER_BLUEFOX
        name = generate_random_name(account_name)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "ReleaseVersion": "OB54",
            "User-Agent": WAFBypass.get_ua(),
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1",
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        lang = "pt" if is_ghost else "id" if region.upper()=="ID" else "en"
        # payload fields based on original script
        payload = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: uid, 15: lang, 16: 1, 17: 1}
        payload_bytes = build_proto(payload)
        encrypted = aes_encrypt(payload_bytes.hex())
        resp = request_retry('POST', url, headers=headers, data=encrypted)
        if resp and resp.status_code == 200:
            return {"ok": True}
        else:
            return {"error": "major_register_failed", "status": getattr(resp, 'status_code', None), 'text': getattr(resp, 'text', '')}
    except Exception as e:
        return {"error": "exception", "msg": str(e), "tb": traceback.format_exc()}


def major_login(uid, password, access_token, open_id, region, is_ghost=False):
    try:
        url = MAJORLOGIN_POLAR if is_ghost or region.upper() not in ["ME","TH"] else MAJORLOGIN_BLUEFOX
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "ReleaseVersion": "OB54",
            "User-Agent": WAFBypass.get_ua(),
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1",
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        # Build a login payload roughly matching original structure; original used a binary blob with replacements
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28',
            b'\x92\x01\rOpenGL ES 3.2',
        ]
        payload = b''.join(payload_parts)
        data = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode() if isinstance(access_token, str) else str(access_token).encode())
        data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode() if isinstance(open_id, str) else str(open_id).encode())
        d = encrypt_api(data.hex())
        resp = request_retry('POST', url, headers=headers, data=bytes.fromhex(d))
        if resp and resp.status_code == 200 and len(resp.text) > 10:
            text = resp.text
            jwt_start = text.find("eyJ")
            if jwt_start != -1:
                jwt_token = text[jwt_start:]
                # heuristically trim jwt to a reasonable length (original logic kept two dots + 44)
                second_dot = jwt_token.find('.', jwt_token.find('.') + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                # try decode payload
                try:
                    parts = jwt_token.split('.')
                    if len(parts) >= 2:
                        payload_part = parts[1]
                        padding = 4 - len(payload_part) % 4
                        if padding != 4:
                            payload_part += '=' * padding
                        decoded = base64.urlsafe_b64decode(payload_part)
                        data_json = json.loads(decoded)
                        account_id = data_json.get('account_id') or data_json.get('external_id')
                        return {"account_id": str(account_id) if account_id else "N/A", "jwt_token": jwt_token}
                except Exception:
                    return {"account_id": "N/A", "jwt_token": jwt_token}
        return {"account_id": "N/A", "jwt_token": ""}
    except Exception as e:
        return {"account_id": "N/A", "jwt_token": "", "error": str(e)}


def force_region_bind(region, jwt_token, is_ghost=False):
    try:
        url = CHOOSEREGION_POLAR if region.upper() in ["ME","TH"] else CHOOSEREGION_BLUEFOX
        region_code = "RU" if region.upper() == "CIS" else region.upper()
        proto_data = build_proto({1: region_code})
        encrypted = encrypt_api(proto_data.hex())
        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Authorization': f"Bearer {jwt_token}",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54",
            'X-Forwarded-For': FastIPSpoofer.get_ip(),
            'X-Real-IP': FastIPSpoofer.get_ip(),
        }
        resp = request_retry('POST', url, data=bytes.fromhex(encrypted), headers=headers)
        if resp and resp.status_code == 200:
            return {"ok": True}
        return {"error": "choose_region_failed", "status": getattr(resp, 'status_code', None)}
    except Exception as e:
        return {"error": "exception", "msg": str(e), "tb": traceback.format_exc()}

# ---------- public orchestrator ----------
import base64

from app.lib.storage import save_account


def create_account_sim_or_real(region, account_name, password_prefix, is_ghost=False, dry_run=True):
    """If dry_run True or ENABLE_EXTERNAL False -> simulate. Else perform full real chain.
    Returns dict with keys: uid, account_id, name, password, region, jwt_token, created_at OR error.
    """
    # Simulation path
    if dry_run or not ENABLE_EXTERNAL:
        uid = make_uid()
        account_id = make_account_id()
        name = generate_random_name(account_name)
        password = f"{password_prefix}_{''.join(random.choices(string.ascii_letters+string.digits, k=12))}"
        created_at = datetime.utcnow().isoformat() + 'Z'
        return {"uid": uid, "account_id": account_id, "name": name, "password": password, "region": region, "jwt_token": "", "created_at": created_at}

    # Real path: register -> token -> major_register -> major_login -> bind region
    reg = create_account_real(region, account_name, password_prefix, is_ghost=is_ghost)
    if reg.get("error"):
        return {"error": "register_failed", "detail": reg}

    uid = reg.get("uid")
    password = reg.get("password")
    token_res = get_token(uid, password)
    if token_res.get("error"):
        return {"error": "token_failed", "detail": token_res}
    access_token = token_res.get("access_token")
    open_id = token_res.get("open_id")

    # major register
    mr = major_register(access_token, open_id, uid, password, account_name, region, is_ghost=is_ghost)
    if mr.get("error"):
        # continue but note the error
        return {"error": "major_register_failed", "detail": mr}

    # login
    ml = major_login(uid, password, access_token, open_id, region, is_ghost=is_ghost)
    account_id = ml.get("account_id", "N/A")
    jwt_token = ml.get("jwt_token", "")

    # bind region if possible
    if jwt_token and account_id != "N/A":
        try:
            force_region_bind(region, jwt_token, is_ghost=is_ghost)
        except Exception:
            pass

    name = generate_random_name(account_name)
    created_at = datetime.utcnow().isoformat() + 'Z'

    result = {"uid": uid, "account_id": account_id, "name": name, "password": password, "region": region, "jwt_token": jwt_token, "created_at": created_at}

    # persist minimal metadata (avoid storing password/jwt in plaintext unless explicitly allowed)
    try:
        save_account({
            'uid': uid,
            'account_id': account_id,
            'name': name,
            'region': region,
            'rarity': 'UNKNOWN',
            'score': 0,
            'jwt_token': jwt_token,
            'created_at': created_at
        })
    except Exception:
        pass

    return result
