module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method === 'GET') return res.json({status: "DARAE V11 API LEAK ✅"});

  const { url } = req.body || {};
  let target = (url || '').trim();
  if (!target) return res.json({error:'حط رابط'});
  if (!target.startsWith('http')) target = 'https://' + target;

  let score = 100;
  let vulns = [];
  let good = [];

  const add = (lvl, name, proof, fix) => {
    vulns.push({level:lvl, name, proof, fix});
    score -= lvl==='high'?30:lvl==='medium'?15:5;
  };

  try {
    let r = await fetch(target, {headers:{'User-Agent':'Mozilla/5.0'}, signal: AbortSignal.timeout(10000)});
    let headers = Object.fromEntries(r.headers.entries());
    let html = await r.text();

    // الفحوصات القديمة السريعة
    try {
      let httpUrl = target.replace('https://','http://');
      let rHttp = await fetch(httpUrl, {redirect:'manual', signal: AbortSignal.timeout(3000)});
      if (rHttp.status === 200) add('high','يقبل HTTP','يفتح بدون تحويل','اجبر HTTPS');
    } catch(e){}
    if (headers['server']) add('low','كشف السيرفر',headers['server'],'ServerTokens Prod');
    if (!headers['content-security-policy']) add('medium','بدون CSP','مافي حماية','اضف CSP');
    if (!headers['x-frame-options']) add('low','Clickjacking','بدون حماية','DENY');

    // SQLi + XSS + Redirect
    try {
      let testUrl = target + (target.includes('?')?'&':'?') + `id='`;
      let resTest = await fetch(testUrl, {signal: AbortSignal.timeout(4000)});
      let body = await resTest.text();
      if (/SQL syntax|mysql_fetch|ORA-|SQLSTATE/i.test(body)) add('high','SQL Injection','خطأ SQL','Prepared Statements');
    } catch(e){}
    try {
      let payload = '<dar9eXSS123>';
      let xssUrl = target + (target.includes('?')?'&':'?') + `q=${encodeURIComponent(payload)}`;
      let rXss = await fetch(xssUrl, {signal: AbortSignal.timeout(4000)});
      let bXss = await rXss.text();
      if (bXss.includes(payload) && !bXss.includes('&lt;dar9eXSS123')) add('high','Reflected XSS','بدون تنظيف','htmlspecialchars()');
    } catch(e){}

    // === الجديد V11: فحص تسريب API Keys ===

    // نجمع كل ملفات JS في الصفحة
    let jsUrls = [];
    let regex = /<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi;
    let m;
    while ((m = regex.exec(html)) !== null) {
      let jsUrl = m[1];
      if (jsUrl.startsWith('/')) jsUrl = target.replace(/\/$/,'') + jsUrl;
      else if (!jsUrl.startsWith('http')) jsUrl = target.replace(/\/$/,'') + '/' + jsUrl;
      jsUrls.push(jsUrl);
      if (jsUrls.length >= 5) break; // نفحص 5 ملفات بس عشان السرعة
    }

    let allJsContent = html; // نفحص الـ HTML نفسه كمان
    for (let jsUrl of jsUrls) {
      try {
        let rJs = await fetch(jsUrl, {signal: AbortSignal.timeout(4000)});
        let jsText = await rJs.text();
        allJsContent += "\n" + jsText.slice(0, 50000); // اول 50k حرف
      } catch(e){}
    }

    // انماط المفاتيح الخطيرة
    const patterns = [
      {name:'Google Maps API Key', regex:/AIza[0-9A-Za-z\-_]{35}/, fix:'احذف المفتاح من JS وضع حد للمفتاح في Google Cloud Console + HTTP Referrer'},
      {name:'AWS Access Key', regex:/AKIA[0-9A-Z]{16}/, fix:'احذف فورا! هذا يكلفك آلاف الدولارات. روح AWS IAM واحذف المفتاح'},
      {name:'Stripe Secret Key', regex:/sk_live_[0-9a-zA-Z]{24,}/, fix:'هذا مفتاح دفع! احذفه فورا واستخدم متغير بيئة'},
      {name:'Slack Token', regex:/xox[bpras]-[0-9A-Za-z\-]{10,}/, fix:'احذف التوكن من الكود'},
      {name:'Private Key', regex:/-----BEGIN PRIVATE KEY-----/, fix:'مفتاح خاص مكشوف! احذفه فورا من الموقع'},
      {name:'Firebase URL', regex:/https:\/\/[a-z0-9\-]+\.firebaseio\.io/, fix:'تأكد قواعد Firebase ليست public'},
      {name:'OpenAI Key', regex:/sk-[a-zA-Z0-9]{20,}T3BlbkFJ/, fix:'مفتاح OpenAI مكشوف! احذفه'},
    ];

    for (let p of patterns) {
      let match = allJsContent.match(p.regex);
      if (match) {
        add('high',`تسريب: ${p.name}`,`وجدنا: ${match[0].slice(0,30)}... في ملفات JS`,p.fix);
      }
    }

    // فحص .env مكشوف (بدون قاموس كبير، فقط .env واحد لأنه اخطر ملف)
    try {
      let envUrl = target.replace(/\/$/,'') + '/.env';
      let rEnv = await fetch(envUrl, {signal: AbortSignal.timeout(3000)});
      if (rEnv.status===200) {
        let bEnv = await rEnv.text();
        if (/DB_PASSWORD|APP_KEY|SECRET/i.test(bEnv)) {
          add('high','ملف .env مكشوف!','فيه باسوردات قواعد البيانات','احذف .env من public_html فورا');
        }
      }
    } catch(e){}

    if (score<0) score=0;
    return res.json({
      score,
      level: score<30?'🔴 خطير جدا':score<60?'🟠 خطر':score<85?'🟡 متوسط':'🟢 آمن',
      target,
      method: 'V11 - 9 فحوصات + تسريب مفاتيح',
      scannedJsFiles: jsUrls.length,
      total: vulns.length,
      vulnerabilities: vulns,
      good
    });

  } catch(err){ return res.json({score:0, error: err.message}); }
};
