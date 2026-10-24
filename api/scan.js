module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    return res.end();
  }

  // قراءة الـ body يدوياً لـ Vercel
  let body = {};
  try {
    if (req.body) body = req.body;
    else {
      let chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      if (chunks.length) body = JSON.parse(Buffer.concat(chunks).toString());
    }
  } catch(e){}

  const { url, code } = body || {};
  let target = (url || '').trim();
  if (!target && !code) {
    res.setHeader('Content-Type','application/json');
    return res.end(JSON.stringify({score:0,label:'خطأ',color:'critical',logs:['حط رابط'],findings:[]}));
  }
  if (target && !target.startsWith('http')) target = 'https://' + target;

  let score = 100;
  let findings = [];
  let logs = ['[DARAE V11] بدأ الفحص','فحص تسريب المفاتيح مفعل'];

  const add = (risk, name, desc, evidence) => {
    findings.push({risk, name, desc, evidence});
    score -= risk==='critical'||risk==='high'?30:risk==='medium'?15:5;
    logs.push(`[!] ${name}`);
  };

  try {
    if (target) {
      let r = await fetch(target, {headers:{'User-Agent':'Mozilla/5.0'}, signal: AbortSignal.timeout(10000)});
      let headers = Object.fromEntries(r.headers.entries());
      let html = await r.text();
      logs.push(`[+] حالة: ${r.status}`);
      logs.push(`[+] حجم الصفحة: ${html.length}`);

      if (headers['server']) add('low','كشف السيرفر',`السيرفر يكشف نفسه`,headers['server']);
      if (!headers['content-security-policy']) add('medium','بدون CSP','الموقع بدون حماية CSP','مافي header');
      if (!headers['x-frame-options']) add('low','Clickjacking','بدون حماية','DENY missing');

      try {
        let testUrl = target + (target.includes('?')?'&':'?') + `id='`;
        let resTest = await fetch(testUrl, {signal: AbortSignal.timeout(4000)});
        let bodyTest = await resTest.text();
        if (/SQL syntax|mysql_fetch|ORA-|SQLSTATE/i.test(bodyTest)) add('high','SQL Injection','خطأ SQL مكشوف',bodyTest.slice(0,200));
      } catch(e){}
      try {
        let payload = '<dar9eXSS123>';
        let xssUrl = target + (target.includes('?')?'&':'?') + `q=${encodeURIComponent(payload)}`;
        let rXss = await fetch(xssUrl, {signal: AbortSignal.timeout(4000)});
        let bXss = await rXss.text();
        if (bXss.includes(payload) && !bXss.includes('&lt;dar9eXSS123')) add('high','Reflected XSS','الكود ينعكس بدون تنظيف',payload);
      } catch(e){}

      let jsUrls = [];
      let regex = /<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi;
      let m;
      while ((m = regex.exec(html)) !== null) {
        let jsUrl = m[1];
        if (jsUrl.startsWith('/')) jsUrl = target.replace(/\/$/,'') + jsUrl;
        else if (!jsUrl.startsWith('http')) jsUrl = target.replace(/\/$/,'') + '/' + jsUrl;
        jsUrls.push(jsUrl);
        if (jsUrls.length >= 5) break;
      }
      logs.push(`[+] فحص ${jsUrls.length} ملفات JS`);
      let allJsContent = html;
      for (let ju of jsUrls) {
        try { let rJs = await fetch(ju, {signal: AbortSignal.timeout(4000)}); allJsContent += "\n" + (await rJs.text()).slice(0,50000); } catch(e){}
      }
      const patterns = [
        {name:'Google Maps Key', regex:/AIza[0-9A-Za-z\-_]{35}/},
        {name:'AWS Access Key', regex:/AKIA[0-9A-Z]{16}/},
        {name:'Stripe Secret', regex:/sk_live_[0-9a-zA-Z]{24,}/},
        {name:'Private Key', regex:/-----BEGIN PRIVATE KEY-----/},
      ];
      for (let p of patterns) {
        let match = allJsContent.match(p.regex);
        if (match) add('high',`تسريب: ${p.name}`,`وجدنا مفتاح مكشوف`,match[0].slice(0,30)+'...');
      }
      try {
        let envUrl = target.replace(/\/$/,'') + '/.env';
        let rEnv = await fetch(envUrl, {signal: AbortSignal.timeout(3000)});
        if (rEnv.status===200) {
          let bEnv = await rEnv.text();
          if (/DB_PASSWORD|APP_KEY|SECRET/i.test(bEnv)) add('critical','ملف .env مكشوف!','فيه باسوردات','/.env موجود');
        }
      } catch(e){}
    }

    if (score<0) score=0;
    let label = score<30?'🔴 خطير جدا':score<60?'🟠 خطر':score<85?'🟡 متوسط':'🟢 آمن';
    let color = score<30?'critical':score<60?'high':score<85?'medium':'safe';

    res.setHeader('Content-Type','application/json');
    return res.end(JSON.stringify({score, label, color, logs, findings}));
  } catch(err){ 
    res.setHeader('Content-Type','application/json');
    return res.end(JSON.stringify({score:0,label:'خطأ',color:'critical',logs:[err.message],findings:[]})); 
  }
};
