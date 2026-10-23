from flask import Flask, render_template, request, jsonify
import socket, ssl, requests, datetime
app = Flask(__name__)
@app.route('/')
def home():
    return render_template('index.html')
@app.route('/scan/<tool>', methods=['POST'])
def scan(tool):
    url=request.json.get('url','')
    domain=url.replace('https://','').replace('http://','').split('/')[0]
    if tool=='php2shell':
        try:
            r=requests.get(url, timeout=5)
            v=r.headers.get('X-Powered-By','مخفي')
            return jsonify({"version":v, "fix":"حدث الى 8.4.27"})
        except Exception as e:
            return jsonify({"error":str(e)})
    return jsonify({"ok":True})
if __name__=='__main__':
    app.run(host='0.0.0.0', port=10000)
