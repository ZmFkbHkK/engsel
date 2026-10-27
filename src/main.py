import hashlib
import hmac
import base64
from base64 import urlsafe_b64encode, urlsafe_b64decode
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from workers import asgi

app = FastAPI(title="Crypto Signature API")

# ==================================================================
# HARDCODED SECRETS (GANTI DENGAN NILAI ASLI ANDA)
# ==================================================================
XDATA_KEY = "5dccbf08920a5527b99e222789c34bb7"
AX_API_SIG_KEY = "18b4d589826af50241177961590e6693"
X_API_BASE_SECRET = "mU1Y4n1vBjf3M7tMnRkFU08mVyUJHed8B5En3EAniu1mXLixeuASmBmKnkyzVziOye7rG5nIekMdthensbQMcOJ6SLnrkGyfXALD7mrBC6vuWv6G01pmD3XlU5rT7Tzx"
# ==================================================================

# ------------------------------------------------------------------
# Model Request
# ------------------------------------------------------------------
class EncryptRequest(BaseModel):
    plaintext: str
    xtime_ms: int

class DecryptRequest(BaseModel):
    xdata: str
    xtime_ms: int

class SignatureRequest(BaseModel):
    id_token: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    sig_time_sec: int

class PaymentSignatureRequest(BaseModel):
    access_token: str
    sig_time_sec: int
    package_code: str
    token_payment: str
    payment_method: str
    payment_for: str
    path: str

class AxSignatureRequest(BaseModel):
    ts_for_sign: str
    contact: str
    code: str
    contact_type: str

# ------------------------------------------------------------------
# Core Crypto Functions (Deterministik)
# ------------------------------------------------------------------
def derive_iv(xtime_ms: int) -> bytes:
    sha = hashlib.sha256(str(xtime_ms).encode()).hexdigest()
    return sha[:16].encode()

def encrypt_xdata(plaintext: str, xtime_ms: int) -> str:
    key_bytes = XDATA_KEY.encode()
    iv = derive_iv(xtime_ms)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), 16, style="pkcs7"))
    return urlsafe_b64encode(ct).decode()

def decrypt_xdata(xdata: str, xtime_ms: int) -> str:
    key_bytes = XDATA_KEY.encode()
    iv = derive_iv(xtime_ms)
    ct = urlsafe_b64decode(xdata + "=" * ((4 - len(xdata) % 4) % 4))
    pt = AES.new(key_bytes, AES.MODE_CBC, iv).decrypt(ct)
    return unpad(pt, 16, style="pkcs7").decode()

def make_x_signature(id_token: str, method: str, path: str, sig_time_sec: int) -> str:
    key_str = f"{X_API_BASE_SECRET};{id_token};{method};{path};{sig_time_sec}"
    msg = f"{id_token};{sig_time_sec};".encode()
    return hmac.new(key_str.encode(), msg, hashlib.sha512).hexdigest()

def make_ax_api_signature(ts_for_sign: str, contact: str, code: str, contact_type: str) -> str:
    key = AX_API_SIG_KEY.encode("ascii")
    preimage = f"{ts_for_sign}password{contact_type}{contact}{code}openid"
    digest = hmac.new(key, preimage.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")

def make_x_signature_payment(req: PaymentSignatureRequest) -> str:
    key_str = f"{X_API_BASE_SECRET};{req.sig_time_sec}#ae-hei_9Tee6he+Ik3Gais5=;POST;{req.path};{req.sig_time_sec}"
    msg = f"{req.access_token};{req.token_payment};{req.sig_time_sec};{req.payment_for};{req.payment_method};{req.package_code};".encode()
    return hmac.new(key_str.encode(), msg, hashlib.sha512).hexdigest()

# ------------------------------------------------------------------
# API Routes (WAJIB async def)
# ------------------------------------------------------------------
@app.get("/")
async def root():
    return {"status": "ok", "service": "Crypto Signature API"}

@app.post("/encrypt")
async def api_encrypt(body: EncryptRequest):
    try:
        result = encrypt_xdata(body.plaintext, body.xtime_ms)
        return {"encrypted": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/decrypt")
async def api_decrypt(body: DecryptRequest):
    try:
        result = decrypt_xdata(body.xdata, body.xtime_ms)
        return {"decrypted": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/signature/general")
async def api_signature_general(body: SignatureRequest):
    if not all([body.id_token, body.method, body.path]):
        raise HTTPException(400, "id_token, method, path wajib diisi")
    sig = make_x_signature(body.id_token, body.method, body.path, body.sig_time_sec)
    return {"signature": sig}

@app.post("/signature/payment")
async def api_signature_payment(body: PaymentSignatureRequest):
    sig = make_x_signature_payment(body)
    return {"signature": sig}

@app.post("/signature/ax")
async def api_signature_ax(body: AxSignatureRequest):
    sig = make_ax_api_signature(body.ts_for_sign, body.contact, body.code, body.contact_type)
    return {"signature": sig}

# ------------------------------------------------------------------
# Entrypoint untuk Cloudflare Workers
# ------------------------------------------------------------------
Default = asgi.entrypoint(app)
