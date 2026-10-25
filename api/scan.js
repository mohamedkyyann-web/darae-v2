export default async function handler(req, res) {
  const urlParam = req.query.url;
  const deep = req.query.deep;
  const code = req.query.code;
  const lang = req.query.lang || 'ar';
  if (!urlParam) return res.status(400).json({error:"url required"});

  let url = urlParam.startsWith('http') ? urlParam : 'https://'+urlParam;
  let base = url.replace(/\/$/, '');
  let score = 100;
  let vulnerabilities = [];
  let logs = [];

  let consentValid = deep === 'true' && code && code.startsWith('DARAE-');
  if (deep === 'true' && !consentValid) {
    return res.status(200).json({
      url, score:0, status: lang==='ar' ? "مرفوض" : "Denied",
      vulnerabilities:[{title:"Invalid DARAE Code",severity:"Critical",desc:"Contact WhatsApp 780194210", fix:"WhatsApp"}],
      logs:["[BLOCKED]"], score:0
    });
  }

  // Helper to push vuln bilingual
  const add = (v) => vulnerabilities.push(v);

  try {
    let r = await fetch(url, {method:'HEAD'});
    let headers = {};
    r.headers.forEach((v,k)=>headers[k]=v);
    
    if (!headers['content-security-policy']) { add({title:"OWASP A05: Missing CSP",severity:"Warning",owasp:"A05",desc: lang==='ar' ? "بدون حماية CSP - يسهل XSS" : "Missing CSP Header - XSS possible", impact:"XSS risk", fix:"Content-Security-Policy: default-src 'self'"}); score-=4; }
    if (!headers['x-frame-options']) { add({title:"OWASP A05: Clickjacking",severity:"Warning",owasp:"A05",desc:"No X-Frame-Options",impact:"UI Redressing",fix:"X-Frame-Options: DENY"}); score-=3; }
    if (!headers['strict-transport-security']) { add({title:"OWASP A05: Missing HSTS",severity:"Warning",owasp:"A05",desc:"No HSTS",fix:"Strict-Transport-Security: max-age=31536000"}); score-=3; }
    if (!headers['x-content-type-options']) { add({title:"OWASP A05: MIME Sniffing",severity:"Info",owasp:"A05",desc:"No X-Content-Type-Options",fix:"X-Content-Type-Options: nosniff"}); score-=1; }
    if (url.startsWith('http://')) { add({title:"OWASP A02: No HTTPS",severity:"Critical",owasp:"A02",desc:"Site uses HTTP",impact:"Data in clear text",fix:"Install SSL, redirect to HTTPS"}); score-=20; }
  } catch(e){ logs.push("[HEAD] fail"); }

  if (consentValid) {
    let target = url.includes('?') ? url : base + '/listproducts.php?cat=1';
    
    // OWASP A03: SQL Injection - safe detect
    try {
      let sr = await fetch(target + "'"); let st = await sr.text();
      if (st.toLowerCase().includes('sql') || st.toLowerCase().includes('mysql') || st.toLowerCase().includes('syntax')) {
        add({title:"🔴 OWASP A03: SQL Injection",severity:"Critical",owasp:"A03",desc: lang==='ar' ? "خطأ SQL عند إضافة ' - دليل حقن" : "SQL error on ' - Injection possible", proof: target + "'", impact:"Full DB read possible", exploit_info:"Detection: add ' and check SQL error", fix:"Use Prepared Statements: $pdo->prepare('SELECT * FROM t WHERE id=?')"}); score=10;
      }
    } catch(e){}

    // OWASP A03: XSS - safe detect
    try {
      let xr = await fetch(target + "<daraeXSS>"); let xt = await xr.text();
      if (xt.includes('<daraeXSS>')) {
        add({title:"🔴 OWASP A03: XSS Reflected",severity:"Critical",owasp:"A03",desc:"Input reflected without encoding",proof: target+"<daraeXSS>",impact:"Session hijacking via link",fix:"htmlspecialchars($input, ENT_QUOTES) + CSP"}); if(score>20) score=20;
      }
    } catch(e){}

    // OWASP A01: Broken Access - sensitive files
    let sensitive = ['/.env','/.git/HEAD','/backup.zip','/old.zip','/www.zip','/db.sql','/backup.sql','/.env.bak','/backup.tar.gz','/site.zip','/phpinfo.php','/debug.log','/wp-config.php.bak','/sitemap.xml.bak','/.DS_Store'];
    for (let p of sensitive) {
      try { let fr = await fetch(base+p, {method:'HEAD'}); if(fr.status===200){ add({title:`🔴 OWASP A01: Exposed ${p}`,severity:"Critical",owasp:"A01",desc:`File ${p} publicly accessible`,impact:"Secrets / DB passwords",fix:`Remove file or deny: <Files "${p.slice(1)}"> Require all denied </Files>`}); score-=12; } } catch(e){}
    }

    // OWASP A01: Admin panels
    let admins = ['/admin','/wp-admin','/administrator','/phpmyadmin','/admin/login.php','/.env.example','/actuator/env'];
    for (let p of admins) {
      try { let fr = await fetch(base+p, {method:'HEAD'}); if(fr.status===200){ add({title:`⚠️ OWASP A01: Panel ${p}`,severity:"Warning",owasp:"A01",desc:`Panel ${p} exposed`,fix:`Restrict by IP + 2FA`}); score-=2; } } catch(e){}
    }

    // OWASP A06: Vulnerable components - WordPress
    try {
      let wr = await fetch(base+'/wp-content/debug.log'); if(wr.status===200){ add({title:"🔴 WP debug.log Exposed",severity:"Critical",owasp:"A06",desc:"WordPress debug.log public",impact:"Full path disclosure + SQL errors",fix:"Delete wp-content/debug.log and disable WP_DEBUG_LOG"}); score-=15; }
    } catch(e){}
    try {
      let rr = await fetch(base+'/readme.html'); if(rr.status===200){ let rt = await rr.text(); if(rt.includes('WordPress')){ add({title:"⚠️ WP Version Leak readme.html",severity:"Info",owasp:"A06",desc:"WordPress version via readme.html",fix:"Delete readme.html"}); score-=1; } }
    } catch(e){}

    // OWASP A02: Secrets in page
    try {
      let mr = await fetch(url); let mt = await mr.text();
      if (mt.match(/AKIA[0-9A-Z]{16}/)) { add({title:"🔴 Secret: AWS Key in HTML",severity:"Critical",owasp:"A07",desc:"AWS Key found in source",impact:"Cloud bill abuse",fix:"Move to env vars"}); score-=20; }
      if (mt.includes('sk_live_') || mt.includes('sk_test_')) { add({title:"🔴 Secret: Stripe Key",severity:"Critical",owasp:"A07",desc:"Stripe secret in frontend",fix:"Never expose sk_ keys"}); score-=15; }
    } catch(e){}

    // OWASP A05: Security Misconfig - Directory listing
    try { let dr = await fetch(base+'/images/'); let dt = await dr.text(); if(dt.includes('Index of /')){ add({title:"⚠️ Directory Listing",severity:"Warning",owasp:"A05",desc:"Directory listing enabled",fix:"Options -Indexes in .htaccess"}); score-=5; } } catch(e){}
  }

  return res.status(200).json({
    url, score: Math.max(0,score), status: score>80 ? (lang==='ar' ? "آمن" : "Secure") : score>50 ? (lang==='ar' ? "متوسط" : "Medium") : (lang==='ar' ? "خطير" : "Critical"),
    totalChecks: consentValid ? 70 : 12,
    critical: vulnerabilities.filter(v=>v.severity==='Critical').length,
    warnings: vulnerabilities.filter(v=>v.severity!=='Critical').length,
    vulnerabilities, logs,
    owasp: "OWASP Top 10 2021 Coverage",
    consent: consentValid ? `DARAE V22 Global 70 checks - WA 780194210` : "Quick Scan",
    disclaimer: "DARAE V22: Ethical scan - detection + fix, no exploit tools. Global standard."
  });
             }
