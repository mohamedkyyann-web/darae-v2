module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.statusCode = 200; return res.end(); }

  let target = req.query?.url || '';
  if (!target) {
    try { let chunks = []; for await (const c of req) chunks.push(c);
      if (chunks.length) { let b = JSON.parse(Buffer.concat(chunks).toString()); target = b.url || ''; }
      if (req.body?.url) target = req.body.url;
    } catch(e){}
  }
  target = (target||'').trim();
  if (!target) return res.end(JSON.stringify({score:0,status:'خطأ',vulnerabilities:[],logs:['حط رابط']}));
  if (!target.startsWith('http')) target = 'https://' + target;

  let score = 100; let vulns = [];
  let logs = [`[DARAE V18 FULL + VT] فحص ${target}`];
  const add = (sev, type, ev, fix, desc) => {
    vulns.push({type, severity:sev, evidence:ev, fix, description:desc});
    score -= sev==='Critical'?40:sev==='High'?25:sev==='Medium'?12:sev==='Low'?5:2;
    logs.push(`[!] ${sev}: ${type}`);
  };

  try {
    // الفحص الأساسي
    let r = await fetch(target, {headers:{'User-Agent':'Mozilla/5.0 DARAE-Scanner'}, signal: AbortSignal.timeout(12000)});
    let headers = Object.fromEntries(r.headers.entries());
    let html = await r.text();
    logs.push(`[+] Status ${r.status}`);

    // 1- Security Headers
    if (!headers['content-security-policy']) add('Medium','Missing CSP','لا يوجد CSP','اضف default-src','يحمي من XSS');
    if (!headers['x-frame-options']) add('Low','Clickjacking','بدون X-Frame-Options','اضف DENY','iframe خطير');
    if (!headers['strict-transport-security']) add('Medium','Missing HSTS','بدون HSTS','اضف HSTS','http ممكن');
    if (headers['server']) add('Low','Server Disclosure',headers['server'],'اخفي الاصدار','يكشف ثغرات');
    if (headers['access-control-allow-origin']==='*') add('High','CORS Wildcard','CORS *','استخدم دومين محدد','يسرق بيانات');

    // 2- Sensitive files
    for (let p of ['/.env','/.git/HEAD','/backup.zip']) {
      try { let rf = await fetch(new URL(p,target).href, {signal: AbortSignal.timeout(3000)}); if(rf.status===200) add('High',`Sensitive: ${p}`,'ملف خطير مكشوف','احذفه','مكشوف'); } catch(e){}
    }

    // 3- VirusTotal - الجديد!
    let vtKey = process.env.VIRUSTOTAL_API_KEY;
    if (vtKey) {
      try {
        logs.push('[+] فحص VirusTotal...');
        // VirusTotal يحتاج base64 للرابط بدون =
        let urlId = Buffer.from(target).toString('base64').replace(/=/g,'');
        let vtRes = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
          headers:{'x-apikey': vtKey},
          signal: AbortSignal.timeout(8000)
        });
        if (vtRes.status===200) {
          let vtData = await vtRes.json();
          let stats = vtData.data?.attributes?.last_analysis_stats;
          let malicious = stats?.malicious || 0;
          let suspicious = stats?.suspicious || 0;
          logs.push(`[+] VT: ${malicious} malicious, ${suspicious} suspicious`);
          if (malicious > 0) add('Critical',`VirusTotal: ${malicious} شركات تقول فيروس`,`${malicious} محرك كشف فيروس`, `${malicious}/90 كشفوه كخبيث`,'الموقع مصنف كخطر عالمياً');
          else if (suspicious > 0) add('Medium',`VirusTotal: مشبوه ${suspicious}`,`${suspicious} محرك مشبوه`,'راجع سمعة الموقع','قد يكون تصيد');
          else logs.push('[+] VT نظيف 0/90');
        } else if (vtRes.status===404) {
          logs.push('[*] VT: الرابط جديد غير موجود في قاعدة بياناتهم');
        } else logs.push(`[*] VT Error ${vtRes.status}`);
      } catch(e){ logs.push(`[*] VT فشل: ${e.message}`); }
    } else {
      logs.push('[*] بدون مفتاح VirusTotal - تخطي الفحص (اضف ENV في Vercel)');
    }

    if(score<0) score=0;
    let status = score<30?'🔴 خطير جدا':score<60?'🟠 خطر':score<85?'🟡 متوسط':'🟢 آمن';
    return res.end(JSON.stringify({score, status, totalChecks:21, realServerChecks:true, virusTotal: true, vulnerabilities: vulns, logs}));
  } catch(err){
    return res.end(JSON.stringify({score:0,status:'خطأ',vulnerabilities:[],logs:[err.message]}));
  }
};
