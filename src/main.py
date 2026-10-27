import hashlib
import os
import hmac
import base64
from base64 import urlsafe_b64encode, urlsafe_b64decode
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from workers import asgi

app = FastAPI(title="Crypto Signature API")

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
# Helper: Mengambil key dari Cloudflare bindings (request.scope["env"])
# ------------------------------------------------------------------
def get_keys(request: Request):
    # Cloudflare Workers ASGI menyimpan bindings/secrets di request.scope["env"]
    cf_env = request.scope.get("env")
    
    if not cf_env:
        raise HTTPException(
            status_code=500,
            detail="Environment tidak ditemukan di request scope.",
        )

    # Gunakan getattr karena cf_env adalah JsProxy
    xdata_key = getattr(cf_env, "XDATA_KEY", None)
    ax_key = getattr(cf_env, "AX_API_SIG_KEY", None)
    x_secret = getattr(cf_env, "X_API_BASE_SECRET", None)

    if not all([xdata_key, ax_key, x_secret]):
        raise HTTPException(
            status_code=500,
            detail="Environment secrets belum di-set di Cloudflare Dashboard.",
        )
    return xdata_key, ax_key, x_secret

# ------------------------------------------------------------------
# Core Crypto Functions (Deterministik)
# ------------------------------------------------------------------
def derive_iv(xtime_ms: int) -> bytes:
    sha = hashlib.sha256(str(xtime_ms).encode()).hexdigest()
    return sha[:16].encode()

def encrypt_xdata(request: Request, plaintext: str, xtime_ms: int) -> str:
    key_bytes = get_keys(request)[0].encode()
    iv = derive_iv(xtime_ms)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), 16, style="pkcs7"))
    return urlsafe_b64encode(ct).decode()

def decrypt_xdata(request: Request, xdata: str, xtime_ms: int) -> str:
    key_bytes = get_keys(request)[0].encode()
    iv = derive_iv(xtime_ms)
    ct = urlsafe_b64decode(xdata + "=" * ((4 - len(xdata) % 4) % 4))
    pt = AES.new(key_bytes, AES.MODE_CBC, iv).decrypt(ct)
    return unpad(pt, 16, style="pkcs7").decode()

def make_x_signature(request: Request, id_token: str, method: str, path: str, sig_time_sec: int) -> str:
    secret = get_keys(request)[2]
    key_str = f"{secret};{id_token};{method};{path};{sig_time_sec}"
    msg = f"{id_token};{sig_time_sec};".encode()
    return hmac.new(key_str.encode(), msg, hashlib.sha512).hexdigest()

def make_ax_api_signature(request: Request, ts_for_sign: str, contact: str, code: str, contact_type: str) -> str:
    key = get_keys(request)[1].encode("ascii")
    preimage = f"{ts_for_sign}password{contact_type}{contact}{code}openid"
    digest = hmac.new(key, preimage.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")

def make_x_signature_payment(request: Request, req: PaymentSignatureRequest) -> str:
    secret = get_keys(request)[2]
    key_str = f"{secret};{req.sig_time_sec}#ae-hei_9Tee6he+Ik3Gais5=;POST;{req.path};{req.sig_time_sec}"
    msg = f"{req.access_token};{req.token_payment};{req.sig_time_sec};{req.payment_for};{req.payment_method};{req.package_code};".encode()
    return hmac.new(key_str.encode(), msg, hashlib.sha512).hexdigest()

# ------------------------------------------------------------------
# API Routes
# ------------------------------------------------------------------
@app.get("/")
def root():
    return {"status": "ok", "service": "Crypto Signature API"}

@app.post("/encrypt")
def api_encrypt(body: EncryptRequest, request: Request):
    try:
        result = encrypt_xdata(request, body.plaintext, body.xtime_ms)
        return {"encrypted": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/decrypt")
def api_decrypt(body: DecryptRequest, request: Request):
    try:
        result = decrypt_xdata(request, body.xdata, body.xtime_ms)
        return {"decrypted": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/signature/general")
def api_signature_general(body: SignatureRequest, request: Request):
    if not all([body.id_token, body.method, body.path]):
        raise HTTPException(400, "id_token, method, path wajib diisi")
    sig = make_x_signature(request, body.id_token, body.method, body.path, body.sig_time_sec)
    return {"signature": sig}

@app.post("/signature/payment")
def api_signature_payment(body: PaymentSignatureRequest, request: Request):
    sig = make_x_signature_payment(request, body)
    return {"signature": sig}

@app.post("/signature/ax")
def api_signature_ax(body: AxSignatureRequest, request: Request):
    sig = make_ax_api_signature(request, body.ts_for_sign, body.contact, body.code, body.contact_type)
    return {"signature": sig}

# ------------------------------------------------------------------
# Entrypoint untuk Cloudflare Workers
# ------------------------------------------------------------------
Default = asgi.entrypoint(app)
