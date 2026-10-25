module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  let target = (req.query.url || req.body?.url || '').trim();
  let code = (req.query.code || req.body?.code || '').trim();
  if (!target) return res.json({score:0,label:'حط رابط',color:'critical',findings:[],logs:['حط رابط']});
  if (!target.startsWith('http')) target = 'http://' + target;
  
  let verified = code.toUpperCase().startsWith('DARAE-');
  if (!verified) return res.json({score:0,label:'كود غلط',color:'critical',findings:[],logs:['لازم DARAE-']});

  let score = 100, findings = [], logs = [`[DARAE V25] فحص تلقائي - ${target}`];
  const add = (f) => {
    if(findings.find(x=>x.name===f.name && x.location===f.location)) return;
    findings.push(f);
    score -= f.risk==='critical'?35:f.risk==='high'?25:10;
    logs.push(`[!] ${f.name}`);
  };
  const to = (u,t=7000) => Promise.race([fetch(u,{headers:{'User-Agent':'Mozilla/5.0 DARAE'}}),new Promise((_,r)=>setTimeout(()=>r(new Error('timeout')),t))]);

  try {
    let r = await to(target, 10000);
    let html = await r.text();
    let headers={}; r.headers.forEach((v,k)=>headers[k]=v);
    logs.push(`[+] فتح ${r.status}`);

    // 1- هيدرات
    if(!headers['content-security-policy']) add({risk:'medium',name:'بدون CSP',location:target, payload:'Content-Security-Policy', evidence:'غير موجود', desc:'بدون حماية XSS', fix:'أضف CSP في htaccess'});
    if(!headers['x-frame-options']) add({risk:'medium',name:'Clickjacking',location:target, payload:'X-Frame-Options', evidence:'غير موجود', desc:'يفتح في iframe', fix:'SAMEORIGIN'});

    // 2- فحص تلقائي لكل البارامترات في الرابط
    try{
      let urlObj = new URL(target);
      logs.push(`[+] وجد ${urlObj.searchParams.size} بارامتر`);
      for(let [key, val] of urlObj.searchParams.entries()){
        try{
          // نجرب نضيف ' للبارامتر الحالي
          let testUrl = target.replace(`${key}=${encodeURIComponent(val)}`, `${key}=${encodeURIComponent(val)}'`);
          // لو ما تغير (عشان ترميز) جرب طريقة ثانية
          if(testUrl===target) testUrl = target + "'";
          
          let rr = await to(testUrl, 7000);
          let bb = await rr.text();
          if(/sql syntax|mysql_fetch|mysqli|ora-|unclosed quotation|warning.*mysql|you have an error in your sql/i.test(bb)){
            add({risk:'high',name:`SQL Injection في بارامتر ${key}`,location:testUrl, payload:`${key}=${val}'`, evidence: bb.match(/.{0,40}sql.{0,60}/i)?.[0]||'رسالة خطأ SQL', desc:`البارامتر ${key} يتأثر بعلامة ' - لازم تحميه`, fix:`استخدم: $id = intval($_GET['${key}']); أو $pdo->prepare("SELECT * WHERE ${key} = ?")`});
          }
          // فحص XSS بسيط - هل القيمة ترجع في الصفحة
          if(bb.includes(val) && val.length>2){
             logs.push(`[?] ${key} يرجع في الصفحة - راجع XSS يدوياً`);
          }
        }catch(e){ logs.push(`[-] ${key}: ${e.message}`); }
      }
    }catch(e){ logs.push('فحص بارامتر: '+e.message); }

    // 3- ملفات حساسة
    let baseOrigin = new URL(target).origin;
    let fileTests = [
      [baseOrigin+'/.env','.env مكشوف','critical','فيه باسورد قاعدة البيانات','احذفه فوراً'],
      [baseOrigin+'/admin/','لوحة /admin','high','لوحة تحكم مكشوفة','غير اسمها'],
      [baseOrigin+'/wp-admin/','ووردبريس','medium','/wp-admin موجود','ركب حماية'],
      [baseOrigin+'/phpinfo.php','phpinfo','high','يكشف معلومات السيرفر','احذفه'],
    ];
    await Promise.all(fileTests.map(async ([url,name,risk,desc,fix])=>{
      try{ let rr=await to(url,5000); let bb=await rr.text(); if(rr.status===200 && bb.length>200 && !bb.includes('404') && !bb.includes('Not Found')){ if(url.includes('.env') && !/DB_|APP_/i.test(bb)) return; if(url.includes('wp-admin') && !/wp-login/i.test(bb)) return; add({risk,name,location:url, payload:url, evidence:bb.slice(0,150), desc, fix}); } }catch(e){}
    }));

    if(score<0) score=0;
    let label = score<30?'🔴 خطير جدا':score<60?'🟠 خطر':score<85?'🟡 متوسط':'🟢 آمن';
    let color = score<30?'critical':score<60?'high':score<85?'medium':'safe';
    return res.json({score,label,color,verified:true,target,logs,findings,totalChecks:20});

  } catch(err){
    return res.json({score:0,label:'ما فتح',color:'critical',logs:[err.message],findings:[]});
  }
};
