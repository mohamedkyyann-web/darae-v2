module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { url } = req.body || {};
  let target = (url || '').trim();
  if (!target) return res.json({score:0,label:'خطأ',color:'critical',logs:['حط رابط'],findings:[]});
  if (!target.startsWith('http')) target = 'https://' + target;

  let score = 100; let findings = []; let logs = ['[DARAE V15] فحص 20 ثغرة','يفحص حماية PHP كاملة'];
  const add = (risk, name, desc, evidence, fix) => {
    if(findings.find(f=>f.name===name)) return;
    findings.push({risk, name, desc, evidence: (evidence||'').slice(0,300), fix: fix||''});
    score -= risk==='critical'?35:risk==='high'?25:risk==='medium'?15:5;
    logs.push(`[!] ${name} [${risk}]`);
  };

  try {
    let r = await fetch(target, {headers:{'User-Agent':'Mozilla/5.0 DARAE'}, signal: AbortSignal.timeout(9000)});
    let headers = Object.fromEntries(r.headers.entries());
    let html = await r.text();
    logs.push(`[+] ${r.status} | ${html.length} byte | فحص ${target}`);

    // 1-3 حمايات
    if (headers['server']) add('low','كشف السيرفر',headers['server'],headers['server'],'nginx: server_tokens off;');
    if (!headers['content-security-policy']) add('medium','بدون CSP','بدون حماية XSS','missing','Header set Content-Security-Policy "default-src \'self\'"');
    if (!headers['x-frame-options']) add('medium','Clickjacking','بدون حماية','missing','Header set X-Frame-Options DENY');

    // 4-5 redirect حقيقي فقط
    try {
      let testUrl = target + (target.includes('?')?'&':'?') + `url=${encodeURIComponent('https://evil.com')}`;
      let rRed = await fetch(testUrl, {redirect:'manual', signal: AbortSignal.timeout(4000)});
      let loc = rRed.headers.get('location')||'';
      if(loc.includes('evil.com')) add('high','Open Redirect','يحول لموقع شرير',loc,'تحقق من باراميتر url');
    } catch(e){}
    try {
      let corsTest = await fetch(target, {headers:{Origin:'https://evil.com'}, signal: AbortSignal.timeout(4000)});
      if((corsTest.headers.get('access-control-allow-origin')||'').includes('evil.com')) add('high','CORS خطير','يسمح بسرقة البيانات','evil.com allowed','غير CORS لـ domain محدد');
    } catch(e){}

    // 6-7 ملفات خطيرة
    try { let rInfo = await fetch(new URL('/phpinfo.php', target).href, {signal: AbortSignal.timeout(3000)}); if(rInfo.status===200 && (await rInfo.clone().text()).toLowerCase().includes('php version')) add('high','phpinfo مكشوف','يكشف معلومات السيرفر','/phpinfo.php','احذف الملف'); } catch(e){}
    try { let rEnv = await fetch(new URL('/.env', target).href, {signal: AbortSignal.timeout(3000)}); let bEnv = await rEnv.text(); if(rEnv.status===200 && /DB_PASSWORD|APP_KEY/i.test(bEnv)) add('critical','.env مكشوف!','كل الباسوردات مكشوفة','/.env','احذفه وامنع الوصول'); } catch(e){}

    // === 8-14 فحوصات PHP الجديدة ===
    try { let rComp = await fetch(new URL('/composer.json', target).href, {signal: AbortSignal.timeout(3000)}); let bComp = await rComp.text(); if(rComp.status===200 && bComp.includes('"require"')) add('medium','composer.json مكشوف','يكشف مكتباتك',bComp.slice(0,100),'امنع الوصول'); } catch(e){}
    try { let rLog = await fetch(new URL('/storage/logs/laravel.log', target).href, {signal: AbortSignal.timeout(3000)}); if(rLog.status===200 && (await rLog.text()).length > 100) add('critical','Laravel Log مكشوف','فيه الباسوردات','/storage/logs/laravel.log','احذف وامنع /storage'); } catch(e){}
    try { let rDebug = await fetch(target + (target.includes('?')?'&':'?') + `debug=1`, {signal: AbortSignal.timeout(3000)}); let bDebug = await rDebug.text(); if(bDebug.includes('APP_DEBUG') || bDebug.includes('Stack trace')) add('high','Debug Mode شغال','يكشف الباسوردات','APP_DEBUG=true','APP_DEBUG=false'); } catch(e){}
    try { let rInfo2 = await fetch(new URL('/info.php', target).href, {signal: AbortSignal.timeout(3000)}); if(rInfo2.status===200 && (await rInfo2.clone().text()).toLowerCase().includes('php version')) add('high','info.php مكشوف','مثل phpinfo','/info.php','احذف الملف'); } catch(e){}
    try { let rBak = await fetch(new URL('/config.php.bak', target).href, {signal: AbortSignal.timeout(3000)}); if(rBak.status===200 && (await rBak.text()).includes('<?php')) add('critical','ملف Backup مكشوف','فيه باسورد DB','config.php.bak','احذف كل .bak'); } catch(e){}
    try { if(headers['x-powered-by'] && headers['x-powered-by'].toLowerCase().includes('php/7')) add('medium','PHP 7 قديمة','فيها ثغرات',headers['x-powered-by'],'حدث لـ PHP 8.2'); } catch(e){}
    try { let rErr = await fetch(target + (target.includes('?')?'&':'?') + `id[]=1`, {signal: AbortSignal.timeout(3000)}); let tErr = await rErr.text(); if(tErr.toLowerCase().includes('fatal error') || tErr.toLowerCase().includes('warning:')) add('low','كشف مسارات PHP','يطلع مسارات داخلية',tErr.slice(0,100),'display_errors=Off'); } catch(e){}

    // 15-16 حقن
    try { let rSqli = await fetch(target + (target.includes('?')?'&':'?') + `id='`, {signal: AbortSignal.timeout(4000)}); if(/SQL syntax|mysql_fetch|ORA-|SQLSTATE/i.test(await rSqli.text())) add('high','SQL Injection','قاعدة البيانات مكشوفة','SQL error','prepared statements'); } catch(e){}
    try { let rXss = await fetch(target + (target.includes('?')?'&':'?') + `q=${encodeURIComponent('<dar9eXSS123>')}`, {signal: AbortSignal.timeout(4000)}); if((await rXss.text()).includes('<dar9eXSS123>')) add('high','Reflected XSS','حقن كود','<dar9eXSS123>','htmlspecialchars()'); } catch(e){}

    // 17 LFI
    try { let testUrl = target + (target.includes('?')?'&':'?') + `file=../../../../etc/passwd`; let rr = await fetch(testUrl, {signal: AbortSignal.timeout(4000)}); if((await rr.text()).includes('root:x:')) add('critical','LFI','قراءة ملفات السيرفر','/etc/passwd','امنع ..'); } catch(e){}

    // 18-20 تسريب مفاتيح
    let m1 = html.match(/AIza[0-9A-Za-z\-_]{35}/); if(m1) add('high','تسريب Google Key',m1[0].slice(0,20),'','احذف المفتاح');
    let m2 = html.match(/AKIA[0-9A-Z]{16}/); if(m2) add('critical','تسريب AWS Key',m2[0],'','غيره فوراً');
    let m3 = html.match(/sk_live_[0-9a-zA-Z]{20,}/); if(m3) add('critical','تسريب Stripe',m3[0].slice(0,20),'','غيره في Dashboard');

    if (score<0) score=0;
    let label = score<30?'🔴 خطير جدا':score<60?'🟠 خطر':score<85?'🟡 متوسط':'🟢 آمن';
    let color = score<30?'critical':score<60?'high':score<85?'medium':'safe';
    logs.push(`[=] انتهى الفحص | النتيجة: ${score}/100`);
    return res.json({score, label, color, logs, findings});
  } catch(err){ return res.json({score:0,label:'خطأ',color:'critical',logs:[err.message],findings:[]}); }
};
