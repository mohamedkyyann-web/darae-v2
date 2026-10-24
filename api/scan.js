module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.statusCode = 200; return res.end(); }

  // يدعم GET ?url= و POST {url}
  let target = '';
  if (req.query && req.query.url) target = req.query.url;
  else {
    try {
      let body = req.body || {};
      if (!Object.keys(body).length) {
        let chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        if (chunks.length) body = JSON.parse(Buffer.concat(chunks).toString());
      }
      target = body.url || body.code || '';
    } catch(e){}
  }
  target = (target || '').trim();
  if (!target) {
    res.setHeader('Content-Type','application/json');
    return res.end(JSON.stringify({score:0,status:'خطأ',totalChecks:0,realServerChecks:false,vulnerabilities:[],logs:['حط رابط'],findings:[]}));
  }
  if (!target.startsWith('http')) target = 'https://' + target;

  let score = 100;
  let findings = [];
  let vulnerabilities = [];
  let logs = ['[DARAE V16 REAL] بدأ الفحص الحقيقي', `Target: ${target}`];

  const add = (severity, type, desc, evidence, fix) => {
    findings.push({risk:severity.toLowerCase(), name:type, desc, evidence});
    vulnerabilities.push({type, severity, evidence: evidence||desc, fix: fix||'راجع الاعدادات'});
    score -= severity==='Critical'?35:severity==='High'?25:severity==='Medium'?12:4;
    logs.push(`[!] ${type} - ${severity}`);
  };

  try {
    let r = await fetch(target, {headers:{'User-Agent':'Mozilla/5.0'}, signal: AbortSignal.timeout(12000)});
    let headers = Object.fromEntries(r.headers.entries());
    let html = await r.text();
    logs.push(`[+] Status: ${r.status} Size: ${html.length}`);

    if (headers['server']) add('Low','Server Disclosure',`السيرفر: ${headers['server']}`,headers['server'],'اخفي Server header');
    if (!headers['content-security-policy']) add('Medium','Missing CSP','بدون حماية CSP','No CSP header','اضف Content-Security-Policy');
    if (!headers['x-frame-options']) add('Low','Clickjacking','بدون X-Frame-Options','Missing','اضف X-Frame-Options: DENY');

    // SQLi Test
    try {
      let t = target + (target.includes('?')?'&':'?') + `id='`;
      let rr = await fetch(t, {signal: AbortSignal.timeout(5000)});
      let bb = await rr.text();
      if (/SQL syntax|mysql_fetch|ORA-|SQLSTATE/i.test(bb)) add('High','SQL Injection','خطأ SQL مكشوف',bb.slice(0,200),'استخدم Prepared Statements');
    } catch(e){}
    // XSS Test
    try {
      let payload = '<daraeXSS123>';
      let x = target + (target.includes('?')?'&':'?') + `q=${encodeURIComponent(payload)}`;
      let rx = await fetch(x, {signal: AbortSignal.timeout(5000)});
      let bx = await rx.text();
      if (bx.includes(payload)) add('High','Reflected XSS','المعامل ينعكس بدون تنظيف',payload,'اعمل HTML Escape');
    } catch(e){}

    // .env check
    try {
      let er = await fetch(target.replace(/\/$/,'') + '/.env', {signal: AbortSignal.timeout(3000)});
      if (er.status===200) {
        let be = await er.text();
        if (/DB_PASSWORD|APP_KEY|SECRET/i.test(be)) add('Critical','.env Exposed','ملف .env مكشوف!','/.env موجود','احذف .env من public');
      }
    } catch(e){}

    // JS Keys leak
    let jsMatch = html.match(/<script[^>]+src=["']([^"']+\.js)[^"']*["']/gi) || [];
    let allJs = html;
    for (let i=0;i<Math.min(jsMatch.length,3);i++){
      try{
        let u = jsMatch[i].match(/src=["']([^"']+)["']/)[1];
        if (u.startsWith('/')) u = new URL(u, target).href;
        else if (!u.startsWith('http')) u = new URL(u, target).href;
        let rj = await fetch(u, {signal: AbortSignal.timeout(4000)});
        allJs += (await rj.text()).slice(0,50000);
      }catch(e){}
    }
    const patterns = [
      {name:'Google Maps Key', regex:/AIza[0-9A-Za-z\-_]{35}/},
      {name:'AWS Key', regex:/AKIA[0-9A-Z]{16}/},
      {name:'Stripe Secret', regex:/sk_live_[0-9a-zA-Z]{24,}/},
      {name:'Private Key', regex:/-----BEGIN PRIVATE KEY-----/},
    ];
    for (let p of patterns){
      let m = allJs.match(p.regex);
      if (m) add('High',`تسريب: ${p.name}`,`مفتاح مكشوف`,m[0].slice(0,30)+'...','احذف المفتاح من الكود');
    }

    if (score<0) score=0;
    let status = score<30?'🔴 خطير جدا':score<60?'🟠 خطر':score<85?'🟡 متوسط':'🟢 آمن';

    res.setHeader('Content-Type','application/json');
    return res.end(JSON.stringify({
      score, status, label:status, color: score<30?'critical':score<60?'high':score<85?'medium':'safe',
      totalChecks: 8, realServerChecks:true,
      vulnerabilities, findings, logs
    }));
  } catch(err){
    res.setHeader('Content-Type','application/json');
    return res.end(JSON.stringify({score:0,status:'خطأ',totalChecks:0,realServerChecks:false,vulnerabilities:[],logs:[err.message],findings:[]}));
  }
};
