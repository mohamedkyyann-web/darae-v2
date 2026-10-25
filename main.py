from flask import Flask, request, jsonify
from flask_cors import CORS
import requests, re
app = Flask(__name__)
CORS(app)
def fetch(u):
 try: return requests.get(u, timeout=10, headers={"User-Agent":"DARAE-V25"}, verify=False, allow_redirects=True)
 except: return None
@app.route("/")
def home(): return jsonify({"status":"LIVE","use":"/api/scan?url=https://yemen.net.ye"})
@app.route("/api/scan")
def scan():
 raw=request.args.get("url","").strip()
 if not raw: return jsonify({"score":0,"findings":[]})
 target=raw if raw.startswith("http") else "https://"+raw
 r=fetch(target)
 if not r: return jsonify({"score":0,"label":"ما يفتح","findings":[]})
 score=100; findings=[]
 def add(risk,name,loc,pay,ev):
  nonlocal score; findings.append({"risk":risk,"name":name,"location":loc,"payload":pay,"evidence":ev}); score-=20 if risk=="high" else 10
 txt=r.text; hdr={k.lower():v for k,v in r.headers.items()}
 r1=fetch(target+("?id=1'" if "?" not in target else "&id=1'"))
 if r1 and re.search(r"sql syntax|mysql|ORA-", r1.text, re.I): add("high","SQL Injection",r1.url,"'","error")
 r2=fetch(target+("?q=<script>alert(1)</script>" if "?" not in target else "&q=<script>alert(1)</script>"))
 if r2 and "<script>alert(1)" in r2.text: add("high","XSS",r2.url,"<script>","reflected")
 if "Index of /" in txt: add("medium","Directory Listing",target,"Index","on")
 if hdr.get("access-control-allow-origin")=="*": add("medium","CORS *",target,"*","*")
 if "x-frame-options" not in hdr: add("medium","Clickjacking",target,"XFO","missing")
 if "content-security-policy" not in hdr: add("medium","CSP Missing",target,"CSP","missing")
 if score<0: score=0
 label=f"🔴 خطير {score}" if score<40 else f"🟠 متوسط {score}" if score<75 else f"🟢 آمن {score}"
 return jsonify({"score":score,"label":label,"target":raw,"findings":findings})
if __name__=="__main__": app.run(host="0.0.0.0", port=5000)
