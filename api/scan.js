module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { url } = req.body || {};
  let target = (url || '').trim();
  if (!target) return res.json({score:0,label:'خطأ',color:'critical',logs:['حط رابط'],findings:[]});
  if (!target.startsWith('http')) target = 'https://' + target;

  let score = 100;
  let findings = [];
  let logs = ['[DARAE V14 PRO] فحص HackerOne','فحص SSRF + LFI + Upload'];

  const add = (risk, name, desc, evidence) => {
    if(findings.find(f=>f.name===name)) return;
    findings.push({risk, name, desc, evidence: (evidence||'').toString().slice(0,400)});
    score -= risk==='critical'?35:risk==='high'?25:risk==='medium'?15:5;
    logs.push(`[!] ${name} [${risk}]`);
  };

  try {
    let r = await fetch(target, {headers:{'User-Agent':'Mozilla/5.0 DARAE'}, signal: AbortSignal.timeout(9000)});
    let headers = Object.fromEntries(r.headers.entries());
    let html = await r.text();
    logs.push(`[+] ${r.status} | ${html.length} byte`);

    // حمايات
    if (headers['server']) add('low','كشف السيرفر',headers['server'],headers['server']);
    if (!headers['content-security-policy']) add('medium','بدون CSP','بدون حماية XSS','missing');
    if (!headers['x-frame-options']) add('medium','Clickjacking','بدون حماية','missing');

    // 1. Open Redirect
    try {
      let testUrl = target + (target.includes('?')?'&':'?') + `url=${encodeURIComponent('https://evil.com')}`;
      let rRed = await fetch(testUrl, {redirect:'manual', signal: AbortSignal.timeout(4000)});
      if((rRed.headers.get('location')||'').includes('evil.com')) add('high','Open Redirect','يحولك لموقع شرير',rRed.headers.get('location'));
    } catch(e){}

    // 2. CORS
    try {
      let corsTest = await fetch(target, {headers:{Origin:'https://evil.com'}, signal: AbortSignal.timeout(4000)});
      if((corsTest.headers.get('access-control-allow-origin')||'').includes('evil.com')) add('high','CORS خطير','يسمح لـ evil.com','evil.com allowed');
    } catch(e){}

    // 3. PHP Checks
    try {
      let rInfo = await fetch(new URL('/phpinfo.php', target).href, {signal: AbortSignal.timeout(3000)});
      if(rInfo.status===200 && (await rInfo.clone().text()).toLowerCase().includes('php version')) add('high','phpinfo مكشوف','يكشف كل معلومات السيرفر','/phpinfo.php');
    } catch(e){}
    try {
      let rEnv = await fetch(new URL('/.env', target).href, {signal: AbortSignal.timeout(3000)});
      let bEnv = await rEnv.text();
      if(rEnv.status===200 && /DB_PASSWORD|APP_KEY/i.test(bEnv)) add('critical','.env مكشوف!','فيه كل الباسوردات','/.env');
    } catch(e){}

    // 4. SQLi + XSS
    try {
      let rSqli = await fetch(target + (target.includes('?')?'&':'?') + `id='`, {signal: AbortSignal.timeout(4000)});
      if(/SQL syntax|mysql_fetch|ORA-|SQLSTATE/i.test(await rSqli.text())) add('high','SQL Injection','خطأ SQL مكشوف','SQL error');
    } catch(e){}
    try {
      let rXss = await fetch(target + (target.includes('?')?'&':'?') + `q=${encodeURIComponent('<dar9eXSS123>')}`, {signal: AbortSignal.timeout(4000)});
      if((await rXss.text()).includes('<dar9eXSS123>')) add('high','Reflected XSS','الكود ينعكس','<dar9eXSS123>');
    } catch(e){}

    // === الجديد V14 ===

    // 5. فحص LFI - Local File Inclusion (ثغرة خطيرة جداً)
    logs.push(`[+] فحص LFI...`);
    try {
      const lfiPayloads = [
        '../../../../etc/passwd',
        '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
        '....//....//etc/passwd'
      ];
      const lfiParams = ['file=','page=','path=','include=','dir=','doc='];
      for(let param of lfiParams){
        for(let payload of lfiPayloads){
          let testUrl = target + (target.includes('?')?'&':'?') + param + payload;
          let rr = await fetch(testUrl, {signal: AbortSignal.timeout(4000)});
          let bb = await rr.text();
          if(bb.includes('root:x:') && bb.includes('/bin/bash')){
            add('critical','LFI - قراءة ملفات السيرفر','يقدر يقرأ /etc/passwd ويسرق كل الملفات',`${param}${payload}`);
            break;
          }
        }
        if(findings.find(f=>f.name.includes('LFI'))) break;
      }
      if(!findings.find(f=>f.name.includes('LFI'))) logs.push(`[+] LFI آمن`);
    } catch(e){}

    // 6. فحص SSRF - Server Side Request Forgery (أخطر ثغرة)
    logs.push(`[+] فحص SSRF...`);
    try {
      // نستخدم خدمة تكشف اذا السيرفر طلبها
      // نفحص هل يقبل يطلب localhost
      const ssrfPayloads = [
        'http://127.0.0.1',
        'http://localhost',
        'http://169.254.169.254/latest/meta-data/', // AWS metadata - أخطر شي
        'http://[::]:80/',
      ];
      const ssrfParams = ['url=','uri=','path=','dest=','redirect=','site=','to=','image=','img='];
      for(let param of ssrfParams){
        for(let payload of ssrfPayloads){
          let testUrl = target + (target.includes('?')?'&':'?') + param + encodeURIComponent(payload);
          let start = Date.now();
          let rr = await fetch(testUrl, {signal: AbortSignal.timeout(5000)});
          let bb = await rr.text();
          // لو رجع بيانات AWS او وقت طويل معناه ثغرة
          if(bb.includes('ami-id') || bb.includes('security-credentials') || bb.includes('root:x:') || (Date.now()-start > 4000 && payload.includes('127.0.0.1'))){
            add('critical','SSRF - يطلب سيرفرات داخلية','يقدر يسرق مفاتيح AWS ويتحكم بالسيرفر',`${param}${payload}`);
            break;
          }
        }
        if(findings.find(f=>f.name.includes('SSRF'))) break;
      }
      if(!findings.find(f=>f.name.includes('SSRF'))) logs.push(`[+] SSRF آمن`);
    } catch(e){}

    // 7. فحص File Upload - هل يسمح برفع ملفات خطيرة؟
    logs.push(`[+] فحص Upload...`);
    if(html.toLowerCase().includes('type="file"') || html.toLowerCase().includes('<input') && html.toLowerCase().includes('upload')){
      add('medium','صفحة رفع ملفات موجودة','لازم تتأكد انها ما تسمح برفع .php','<input type=file> found');
      logs.push(`[!] وجدت فورم رفع ملفات - افحصه يدوياً`);
    }

    // 8. فحص تسريب مفاتيح
    const patterns = [
      {name:'Google Maps', regex:/AIza[0-9A-Za-z\-_]{35}/},
      {name:'AWS Key', regex:/AKIA[0-9A-Z]{16}/},
      {name:'Stripe', regex:/sk_live_[0-9a-zA-Z]{24,}/},
    ];
    for(let p of patterns){
      let m = html.match(p.regex);
      if(m) add('high',`تسريب: ${p.name}`,m[0].slice(0,20)+'...',m[0].slice(0,40));
    }

    if (score<0) score=0;
    let label = score<30?'🔴 خطير جدا':score<60?'🟠 خطر':score<85?'🟡 متوسط':'🟢 آمن';
    let color = score<30?'critical':score<60?'high':score<85?'medium':'safe';
    return res.json({score, label, color, logs, findings});
  } catch(err){ 
    return res.json({score:0,label:'خطأ',color:'critical',logs:[err.message],findings:[]}); 
  }
};
