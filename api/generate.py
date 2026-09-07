# -*- coding: utf-8 -*-

import hmac
import hashlib
import random
import json
import codecs
import time
import base64
import threading
import re
import sys
import os
import socket
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# ENGINE DARI SC2 (LENGKAP) – diambil dari a.py
# ============================================================

# ---------- OPTIMIZATION ----------
OPT = {'timeout': 0.9, 'retries': 0, 'backoff': 0.01}

# ---------- IP SPOOFER ----------
class FastIPSpoofer:
    _IP_POOL = []
    _IP_INDEX = 0
    _IP_LOCK = threading.Lock()
    @classmethod
    def init_ip_pool(cls, count=5000):
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
FastIPSpoofer.init_ip_pool(5000)

class WAFBypass:
    _versions = ["4.0.19P8", "4.0.39", "4.0.40"]
    _android_versions = ["11", "12", "13", "14"]
    _regions = ["HK", "ID", "SG", "MY", "PH", "TH", "VN"]
    _devices = [
        "SM-A325M", "SM-A525F", "SM-A536B", "SM-A736B", "SM-A715F", "SM-A725F",
        "SM-A515F", "SM-A127F", "SM-A226B", "SM-A326B", "SM-M325F", "SM-M515F",
        "SM-G991B", "SM-G996B", "SM-G998B", "SM-S901B", "SM-S906B", "SM-S908B",
        "SM-G781B", "SM-G770F", "SM-G973F", "SM-G960F", "SM-N986B", "SM-N976B",
        "SM-F711B", "SM-F926B", "SM-F731B", "SM-F936B",
        "M2012K11AG", "M2101K7AG", "MZB08A",
        "Redmi Note 9", "Redmi Note 10", "Redmi Note 11", "Redmi Note 12",
        "Redmi 8", "Redmi 9", "Redmi 10",
        "Poco X3", "Poco X3 Pro", "POCO F3", "POCO F4", "POCO M3", "POCO M4 Pro",
        "11T Pro", "Mi 11", "Mi 11 Lite", "Mi 12", "Mi 13",
        "CPH2249", "CPH2333", "CPH2025",
        "OPPO A74", "OPPO A96", "OPPO A77", "OPPO Reno5", "OPPO Reno6",
        "OPPO Reno7", "OPPO Reno8", "OPPO F19", "OPPO F21 Pro",
        "V2046", "V2050", "V2024",
        "vivo 1906", "vivo V21", "vivo V23", "vivo V25", "vivo Y72", "vivo Y20",
        "vivo Y75", "vivo Y55", "vivo X60", "vivo T1",
        "RMX3370", "RMX3392", "RMX2020", "RMX3081",
        "realme 7", "realme 8", "realme 9", "realme GT", "realme GT Neo",
        "realme 9 Pro", "realme 9i", "realme C25", "realme C31", "realme C35",
        "Pixel 4a", "Pixel 5", "Pixel 6", "Pixel 6a", "Pixel 7", "Pixel 7 Pro",
        "OnePlus 8", "OnePlus 8T", "OnePlus 9", "OnePlus 10 Pro",
        "OnePlus Nord", "OnePlus Nord 2",
        "Nokia 8.1", "Nokia 7.2", "Nokia 6.2", "Nokia X20", "Nokia X10", "Nokia G50",
        "ASUS_Z01QD", "Asus ZenFone 8", "Asus ZenFone 9",
        "Asus ROG Phone 5", "Asus ROG Phone 6",
        "Infinix X6815", "Infinix X6831", "Infinix Zero 5G",
        "TECNO KI5q", "TECNO CK8n", "Tecno Camon 19",
        "Nothing Phone (1)"
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
                        ua_list.append(
                            f"GarenaMSDK/{v}({device};Android {android};en;{region};)"
                        )
        cls._UA_CACHE = ua_list
        return ua_list

    @staticmethod
    def get_ua():
        ua_list = WAFBypass._build_ua_list()
        return random.choice(ua_list)

session = requests.Session()
# Konfigurasi retry untuk session
retry_strategy = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=50, pool_maxsize=50)
session.mount("http://", adapter)
session.mount("https://", adapter)

def request_retry(method, url, **kwargs):
    for attempt in range(OPT['retries'] + 1):
        try:
            if 'timeout' not in kwargs:
                kwargs['timeout'] = OPT['timeout']
            if 'headers' not in kwargs:
                kwargs['headers'] = {}
            kwargs['verify'] = False
            resp = session.request(method, url, **kwargs)
            if resp.status_code in [429,500,502,503,504,408]:
                if attempt < OPT['retries']:
                    time.sleep(OPT['backoff'] * (attempt + 1))
                    continue
            return resp
        except:
            if attempt < OPT['retries']:
                time.sleep(OPT['backoff'] * (attempt + 1))
                continue
            return None
    return None

# ---------- ENCRYPTION FUNCTIONS ----------
def encode_varint(n):
    if n < 0: return b''
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n: byte |= 0x80
        result.append(byte)
        if not n: break
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
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def encrypt_api(plain_hex):
    plain = bytes.fromhex(plain_hex)
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain, AES.block_size)).hex()

# ---------- REGION & CONSTANTS ----------
REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"bn","PK":"ur","TW":"zh","CIS":"ru","SAC":"es","BR":"pt"}
HEX_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")

# ---------- WRAPPING PAIRS ----------
WRAPPING_PAIRS = [('꧁','꧂'),('『','』'),('【','】'),('《','》'),('〈','〉'),('〔','〕'),('〖','〗'),('〘','〙'),('〚','〛'),('❬','❭'),('❮','❯'),('⦅','⦆'),('⟦','⟧'),('⟨','⟩'),('⫷','⫸')]
SINGLE_SYMBOLS = ['☆','★','✧','✦','✩','✪','✫','✬','✭','✮','✯','✰','♡','♥','❤','❥','❦','❧','ゝ','々','〆','⁂','※','⁑']

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

# ========== CORE ACCOUNT CREATION (SC2) ==========
def create_account(region, account_name, password_prefix, is_ghost=False):
    try:
        rand_part = "".join(random.choices("0123456789ABCDEF", k=16))
        password = f"{password_prefix}_{rand_part}"
        
        url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
        payload = {
            "app_id": 100067,
            "client_type": 2,
            "password": password,
            "source": 2
        }
        body_json = json.dumps(payload, separators=(",", ":"))
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
        
        resp = request_retry('POST', url, headers=headers, data=body_json)
        if resp and resp.status_code == 200:
            res = resp.json()
            if "data" in res and "uid" in res["data"]:
                uid = res["data"]["uid"]
                return get_token(uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except:
        return None

def get_token(uid, password, region, account_name, password_prefix, is_ghost):
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": WAFBypass.get_ua(),
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": HEX_KEY, "client_id": "100067"}
        resp = request_retry('POST', url, headers=headers, data=body)
        
        if resp and resp.status_code == 200 and 'open_id' in resp.json():
            open_id = resp.json()['open_id']
            access_token = resp.json()["access_token"]
            keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
            encoded = ""
            for i in range(len(open_id)):
                encoded += chr(ord(open_id[i]) ^ keystream[i % len(keystream)])
            field = codecs.decode(''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded), 'unicode_escape').encode('latin1')
            return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except:
        return None

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost):
    try:
        url = "https://loginbp.ggpolarbear.com/MajorRegister" if is_ghost or region.upper() not in ["ME","TH"] else "https://loginbp.common.ggbluefox.com/MajorRegister"
        name = generate_random_name(account_name)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "ReleaseVersion": "OB54",
            "User-Agent": WAFBypass.get_ua(),
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.",
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: field, 15: lang, 16: 1, 17: 1}
        payload_bytes = build_proto(payload)
        encrypted = aes_encrypt(payload_bytes.hex())
        request_retry('POST', url, headers=headers, data=encrypted)
        login_result = major_login(uid, password, access_token, open_id, region, is_ghost)
        account_id = login_result.get("account_id", "N/A")
        jwt_token = login_result.get("jwt_token", "")
        if account_id != "N/A":
            if not is_ghost and jwt_token and region.upper() != "BR":
                try: force_region_bind(region, jwt_token, is_ghost)
                except: pass
            return {
                "uid": uid, 
                "password": password, 
                "name": name,
                "region": "GHOST" if is_ghost else region,
                "account_id": account_id, 
                "jwt_token": jwt_token,
                "created_at": datetime.now().isoformat()
            }
        return None
    except:
        return None

def major_login(uid, password, access_token, open_id, region, is_ghost):
    try:
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        payload = b''.join(payload_parts)
        url = "https://loginbp.ggpolarbear.com/MajorLogin" if is_ghost or region.upper() not in ["ME","TH"] else "https://loginbp.common.ggbluefox.com/MajorLogin"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "ReleaseVersion": "OB54",
            "User-Agent": WAFBypass.get_ua(),
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1",
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        data = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        d = encrypt_api(data.hex())
        resp = request_retry('POST', url, headers=headers, data=bytes.fromhex(d))
        if resp and resp.status_code == 200 and len(resp.text) > 10:
            jwt_start = resp.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = resp.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    try:
                        parts = jwt_token.split('.')
                        if len(parts) >= 2:
                            payload_part = parts[1]
                            padding = 4 - len(payload_part) % 4
                            if padding != 4:
                                payload_part += '=' * padding
                            decoded = base64.urlsafe_b64decode(payload_part)
                            data = json.loads(decoded)
                            account_id = data.get('account_id') or data.get('external_id')
                            if account_id:
                                return {"account_id": str(account_id), "jwt_token": jwt_token}
                    except: pass
        return {"account_id": "N/A", "jwt_token": ""}
    except:
        return {"account_id": "N/A", "jwt_token": ""}

def force_region_bind(region, jwt_token, is_ghost=False):
    try:
        url = "https://loginbp.common.ggbluefox.com/ChooseRegion" if region.upper() in ["ME","TH"] else "https://loginbp.ggpolarbear.com/ChooseRegion"
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
        request_retry('POST', url, data=bytes.fromhex(encrypted), headers=headers)
    except: pass

# ============================================================
# HANDLER UNTUK VERCEL
# ============================================================

def handler(request, context):
    """
    Endpoint untuk generate akun.
    Query params:
      - region      : kode region (default 'ID')
      - count       : jumlah akun (1-10, default 1)
      - name_prefix : prefix nama (default 'moss')
      - pass_prefix : prefix password (default 'moss')
      - ghost       : 'true' untuk mode ghost (default 'false')
    """
    # Ambil parameter
    region = request.query.get('region', 'ID')
    try:
        count = int(request.query.get('count', 1))
    except:
        count = 1
    count = max(1, min(count, 10))   # batasi maksimal 10 agar tidak timeout

    name_prefix = request.query.get('name_prefix', 'moss')
    password_prefix = request.query.get('pass_prefix', 'moss')
    ghost = request.query.get('ghost', 'false').lower() == 'true'

    accounts = []
    for _ in range(count):
        acc = create_account(region, name_prefix, password_prefix, ghost)
        if acc and acc.get('account_id') != 'N/A':
            # ambil data penting
            accounts.append({
                'uid': acc.get('uid'),
                'password': acc.get('password'),
                'account_id': acc.get('account_id'),
                'name': acc.get('name'),
                'region': acc.get('region')
            })
        # beri jeda kecil agar tidak terlalu cepat
        time.sleep(0.05)

    response_body = {
        'success': True,
        'count': len(accounts),
        'accounts': accounts
    }
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json'
        },
        'body': json.dumps(response_body)
    }