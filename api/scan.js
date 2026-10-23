export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  const { url, code } = req.body || {};
  let findings = [];
  let score = 100;
  let logs = [];
  function add(name, risk, desc, ev){
    findings.push({name,risk,desc,evidence:ev});
    if(risk==='critical') score-=25;
    if(risk==='high') score-=15;
    if(risk==='medium') score-=7;
    if(risk==='low') score-=2;
  }
  let content = code || '';
  if(url){
    try{
      logs.push('فحص: '+url);
      let r = await fetch(url, {headers:{'User-Agent':'DARAE-V3'}});
      let t = await r.text();
      content += '\n' + t.slice(0,20000);
      if(!r.headers.get('x-frame-options')) add('Clickjacking مفقود','medium','X-Frame-Options','');
      let origin = new URL(url).origin;
      for(let p of ['/.env','/.git/config','/config.php']){
        try{
          let rr = await fetch(origin+p);
          if(rr.ok){
            let tt = await rr.text();
            if(tt.length>10 && tt.length<5000 && (tt.includes('DB_')||tt.includes('password')||tt.includes('[core]'))){
              add('ملف حساس مكشوف '+p,'critical','ملف إعدادات مكشوف',tt.slice(0,150));
            }
          }
        }catch{}
      }
    }catch(e){ logs.push('خطأ: '+e.message); }
  }
  let pats=[
    [/eval\s*\(/gi,'eval()','critical','تنفيذ كود خطير'],
    [/shell_exec|system\s*\(|exec\s*\(|passthru/gi,'تنفيذ أوامر نظام','critical','RCE'],
    [/base64_decode/gi,'base64_decode','high','إخفاء شيل'],
    [/c99|r57|wso/gi,'شيل معروف','critical','WebShell جاهز'],
    [/include\s*\(.*\$_/gi,'LFI/RFI','critical','تضمين ملفات خطير'],
    [/unserialize\s*\(.*\$_/gi,'Object Injection','critical','Deserialization'],
  ];
  for(let [re,name,risk,desc] of pats){
    let m = content.match(re);
    if(m) add(name,risk,desc,m[0]);
  }
  if(score<0) score=0;
  let label=score>=80?'نظيف':score>=50?'مشبوه':score>=30?'خطير':'مصاب';
  let color=score>=80?'safe':score>=50?'medium':score>=30?'high':'critical';
  return res.status(200).json({score,label,color,findings,logs,scannedLength:content.length});
               }
