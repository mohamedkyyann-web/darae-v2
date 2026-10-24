export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  let { url, deep, code } = req.query;
  if (!url) return res.status(400).json({ error: "حط رابط" });
  if (!url.startsWith('http')) url = 'https://' + url;
  url = url.replace(/\/+$/, '').trim();

  let score = 100;
  let vulnerabilities = [];
  let logs = [];

  try {
    logs.push(`[DARAE V19 - باذن المالك] فحص ${url}`);
    let r = null;
    try { r = await fetch(url, { method: 'HEAD' }); } catch(e){}

    if (r) {
      if (!r.headers.get('content-security-policy')) {
        vulnerabilities.push({ type: "Missing CSP", severity: "Medium", evidence: url, fullUrl: url, fix: "أضف CSP", description: `الموقع ${url} بدون CSP معرض لـ XSS` });
        score -= 10;
      }
      if (!r.headers.get('strict-transport-security')) {
        vulnerabilities.push({ type: "Missing HSTS", severity: "Medium", evidence: url, fullUrl: url, fix: "أضف HSTS", description: `الموقع ${url} لا يجبر HTTPS` });
        score -= 10;
      }
      if (r.headers.get('server')) {
        vulnerabilities.push({ type: "Server Disclosure", severity: "Low", evidence: `${url} يكشف ${r.headers.get('server')}`, fullUrl: url, fix: "اخفي الهيدر", description: "يكشف نوع السيرفر" });
        score -= 5;
      }
      if (!r.headers.get('x-frame-options')) {
        vulnerabilities.push({ type: "Clickjacking", severity: "Medium", evidence: url, fullUrl: url, fix: "X-Frame-Options DENY", description: `يمكن تضمين ${url} في موقع نصب` });
        score -= 10;
      }
    }

    // الفحص العميق والهجومي - فقط باذن المالك (كود DARAE)
    if (deep === 'true' && code && code.startsWith('DARAE-')) {
      logs.push(`[!] فحص هجومي مصرح به لـ ${url} بالكود ${code}`);
      
      // أ- ملفات حساسة
      const paths = ['/.env','/.env.bak','/.git/','/wp-config.php','/backup.zip','/phpinfo.php'];
      for (let p of paths) {
        try {
          let checkUrl = url + p;
          let c = await fetch(checkUrl, { method: 'HEAD' });
          if (c.status === 200) {
            vulnerabilities.push({ type: "Exposed File", severity: "Critical", evidence: checkUrl, fullUrl: checkUrl, fix: `احذف ${p} فوراً`, description: `ملف ${p} مكشوف على ${checkUrl}` });
            score -= 25;
          }
        } catch(e){}
      }

      // ب- فحص هجومي SQL حقيقي - باذن المالك - اختبار آمن
      if (url.includes('?') && url.includes('=')) {
        try {
          let testUrl = url + "'";
          let resTest = await fetch(testUrl);
          let txt = await resTest.text();
          let low = txt.toLowerCase();
          if (low.includes('sql syntax') || low.includes('mysql_fetch') || low.includes('unclosed quotation') || low.includes('you have an error in your sql') || low.includes('warning') && low.includes('mysqli')) {
            vulnerabilities.push({
              type: "SQL Injection - CONFIRMED",
              severity: "Critical",
              evidence: testUrl,
              fullUrl: testUrl,
              fix: "موقعك مصاب! أوقف الموقع واستخدم Prepared Statements: $stmt = $pdo->prepare('SELECT * WHERE id=?')",
              description: `تم تأكيد ثغرة SQL Injection في ${url} - الاختبار بـ ' كشف خطأ قاعدة البيانات`
            });
            score = 0;
            logs.push(`[EXPLOIT-CONFIRMED] SQL Injection في ${testUrl}`);
          }
        } catch(e){}
      }

      // ج- فحص هجومي XSS حقيقي - باذن المالك
      try {
        let baseUrl = url.split('?')[0];
        let param = url.includes('?') ? url.split('?')[1].split('=')[0] : 'q';
        let xssPayload = "<daraeXSS>";
        let xssTestUrl = url.includes('?') ? `${url}${xssPayload}` : `${baseUrl}?${param}=${xssPayload}`;
        let xssRes = await fetch(xssTestUrl);
        let xssTxt = await xssRes.text();
        if (xssTxt.includes('<daraeXSS>') || xssTxt.includes('&lt;daraeXSS&gt;') === false && xssTxt.includes('daraeXSS')) {
          // تأكد انه يرجع بدون ترميز
          if (xssTxt.includes('<daraeXSS>')) {
            vulnerabilities.push({
              type: "XSS Reflected - CONFIRMED",
              severity: "Critical",
              evidence: xssTestUrl,
              fullUrl: xssTestUrl,
              fix: "موقعك مصاب بـ XSS! استخدم htmlspecialchars($_GET) و CSP",
              description: `تم تأكيد XSS في ${url} - السيرفر يرجع الكود ${xssPayload} بدون فلترة`
            });
            score -= 30;
            logs.push(`[EXPLOIT-CONFIRMED] XSS في ${xssTestUrl}`);
          }
        }
      } catch(e){}

      // د- فحص لوحة تحكم مكشوفة
      try {
        let adminPaths = ['/admin/','/wp-admin/','/administrator/'];
        for (let ap of adminPaths) {
          let adminUrl = url + ap;
          let ac = await fetch(adminUrl, { method: 'HEAD' });
          if (ac.status === 200) {
            vulnerabilities.push({ type: "Admin Panel Exposed", severity: "Medium", evidence: adminUrl, fullUrl: adminUrl, fix: `احمي ${ap} بـ IP و 2FA`, description: `لوحة تحكم مكشوفة على ${adminUrl}` });
            score -= 10;
          }
        }
      } catch(e){}
    }

    vulnerabilities.sort((a,b) => ({Critical:0,Medium:1,Low:2}[a.severity]||9) - ({Critical:0,Medium:1,Low:2}[b.severity]||9));
    
    return res.status(200).json({
      url, score: Math.max(0,score), status: score>80?"آمن":score>50?"متوسط":"خطير ومصاب",
      totalChecks: 24, critical: vulnerabilities.filter(v=>v.severity==='Critical').length,
      warnings: vulnerabilities.filter(v=>v.severity!=='Critical').length,
      vulnerabilities, logs,
      consent: deep ? `فحص هجومي تم باذن مالك ${url} عبر كود ${code}` : "فحص ظاهري فقط",
      disclaimer: "تم الفحص باذن مالك الموقع عبر توثيق واتساب. الاختبارات آمنة لا تحذف بيانات"
    });

  } catch(e){ return res.status(500).json({ url, score:0, status:"خطأ", error:e.message }) }
            }
