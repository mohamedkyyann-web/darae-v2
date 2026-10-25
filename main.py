import os, json, re, ipaddress, random, string, time
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app, supports_credentials=True)

ADMIN_TOKEN = "darae_admin_2025_mohamed"
CODES_FILE = "codes.json"
ALLOWED_FILE = "allowed_domains.json"

# انشاء الملفات
for f, default in [(CODES_FILE, {}), (ALLOWED_FILE, ["yemen.net.ye"])]:
    if not os.path.exists(f):
        with open(f, "w") as j:
            json.dump(default, j)

def load_codes():
    with open(CODES_FILE) as f:
        return json.load(f)
def save_codes(c):
    with open(CODES_FILE, "w") as f:
        json.dump(c, f, indent=2)
def load_allowed():
    with open(ALLOWED_FILE) as f:
        return json.load(f)

def gen_code():
    # يولد كود مثل DARAE-A7B9
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"DARAE-{suffix}"

def is_private(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except:
        return False

@app.route("/")
def home():
    return jsonify({"status":"Darae WhatsApp Code System Running"})

@app.route("/healthz")
def healthz():
    return jsonify({"status":"ok"})

# 1- انت تولد رمز للعميل بعد ما يكلمك واتساب
@app.route("/admin/generate-code", methods=["POST"])
def generate_code():
    token = request.headers.get("X-ADMIN-TOKEN") or request.args.get("token") or (request.get_json() or {}).get("token")
    if token != ADMIN_TOKEN:
        return jsonify({"error":"unauthorized"}), 401
    
    data = request.get_json() or {}
    domain = re.sub(r'^https?://','', data.get("domain","").lower()).split('/')[0].strip()
    whatsapp = data.get("whatsapp","").strip()
    
    if not domain:
        return jsonify({"error":"domain required"}), 400

    code = gen_code()
    codes = load_codes()
    codes[code] = {
        "domain": domain,
        "whatsapp": whatsapp,
        "created": int(time.time()),
        "expires": int(time.time()) + 86400*7, # صالح 7 ايام
        "used": 0
    }
    save_codes(codes)
    
    return jsonify({
        "success": True,
        "code": code,
        "domain": domain,
        "whatsapp": whatsapp,
        "message": f"ارسل للعميل: رمزك هو {code} صالح لمدة 7 ايام لفحص {domain}"
    })

# 2- العميل يتحقق من الرمز
@app.route("/api/verify-code", methods=["GET","POST"])
def verify_code():
    data = request.get_json() if request.is_json else {}
    code = (request.args.get("code") or data.get("code") or "").strip().upper()
    
    codes = load_codes()
    if code not in codes:
        return jsonify({"valid": False, "error": "الرمز غير صحيح"}), 404
    
    info = codes[code]
    if info["expires"] < time.time():
        return jsonify({"valid": False, "error": "الرمز انتهى"}), 403
    
    return jsonify({"valid": True, "domain": info["domain"], "expires": info["expires"]})

# 3- الفحص - لازم رمز صحيح
@app.route("/api/scan")
def scan():
    url = request.args.get("url","")
    code = (request.args.get("code") or "").strip().upper()
    
    if not code:
        return jsonify({"error":"الرمز مطلوب. تواصل واتساب للحصول على رمز DARAE-XXXX"}), 401
    
    codes = load_codes()
    if code not in codes:
        return jsonify({"error":"الرمز غير صحيح"}), 403
    
    info = codes[code]
    if info["expires"] < time.time():
        return jsonify({"error":"الرمز انتهى، تواصل واتساب لتجديد"}), 403
    
    # تأكد ان الرابط يتبع الدومين المصرح له
    try:
        host = urlparse(url).hostname or ""
        if info["domain"] not in host and host != info["domain"] and not host.endswith("."+info["domain"]):
            return jsonify({"error": f"هذا الرمز مخصص فقط لـ {info['domain']}"}), 403
        if is_private(host) or host == "localhost":
            return jsonify({"error":"private IP blocked"}), 403
    except:
        return jsonify({"error":"invalid url"}), 400
    
    # عداد الاستخدام
    info["used"] += 1
    codes[code] = info
    save_codes(codes)
    
    return jsonify({
        "url": url,
        "code": code,
        "domain": info["domain"],
        "status": "scanned",
        "used_count": info["used"]
    })

# قائمة الرموز
@app.route("/admin/codes")
def list_codes():
    token = request.headers.get("X-ADMIN-TOKEN") or request.args.get("token")
    if token != ADMIN_TOKEN:
        return jsonify({"error":"unauthorized"}), 401
    return jsonify(load_codes())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
