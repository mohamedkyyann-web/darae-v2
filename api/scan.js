export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  let target=(req.query.url||'').trim();
  let code=(req.query.code||'').trim();
  if(!target) return res.json({score:0,label:'حط رابط',color:'critical',findings:[],logs:[],owasp:'-',cwe:'-'});
  if(!target.startsWith('http')) target='http://'+target;
  if(!code.toUpperCase().startsWith('DARAE-')) return res.json({score:0,label:'كود غلط - لازم DARAE-',color:'critical',findings:[],logs:[],owasp:'-',cwe:'-'});
  
  let score=100,findings=[],logs=[`بدء فحص حقيقي لـ ${target}`];
  const add=(f)=>{findings.push(f); score-=f.risk==='high'?20:f.risk==='medium'?10:5;};
  const get=async(u)=>{try{let r=await fetch(u,{headers:{'User-Agent':'Mozilla/5.0'},signal:AbortSignal.timeout(7000)});let t=await r.text();return {r,t}}catch(e){return {r:{status:0,headers:{get:()=>null}},t:''}}};

  try{
    // 1-2 SQL Injection
    let a1=await get(target+"'"); if(/sql syntax|mysql|mysqli|ORA-|SQLServer|unclosed quotation/i.test(a1.t)){add({risk:'high',name:'SQL Injection',location:target+"'",payload:"' ",evidence:a1.t.slice(0,100),desc:'السيرفر كشف خطأ SQL',fix:'استخدم prepared statements'}); logs.push('✓ SQLi مكشوف');} else logs.push('× SQLi نظيف');
    
    // 3 XSS Reflected
    let xssUrl=target+(target.includes('?')?'&':'?')+'xss=<script>alert(1)</script>'; let a2=await get(xssUrl); if(a2.t.includes('<script>alert(1)')){add({risk:'high',name:'Reflected XSS',location:xssUrl,payload:'<script>alert(1)',evidence:'payload انعكس',desc:'XSS حقيقي',fix:'escape output'}); logs.push('✓ XSS مكشوف');} else logs.push('× XSS نظيف');

    // 4 Open Redirect
    let redUrl=target+(target.includes('?')?'&':'?')+'next=https://evil.com'; let a3=await get(redUrl); if(a3.r.headers.get('location')?.includes('evil.com')||a3.t.includes('evil.com')){add({risk:'high',name:'Open Redirect',location:redUrl,payload:'evil.com',evidence:'تحويل لموقع خارجي',desc:'يخليك تتحول لموقع شرير',fix:'تحقق من الدومين'}); logs.push('✓ Open Redirect');} else logs.push('× Redirect نظيف');

    // 5 LFI
    let lfiUrl=target+(target.includes('?')?'&':'?')+'file=../../../../etc/passwd'; let a4=await get(lfiUrl); if(/root:\/.*:\/bin\/bash/.test(a4.t)){add({risk:'high',name:'LFI - قراءة ملفات النظام',location:lfiUrl,payload:'../../etc/passwd',evidence:'root:x',desc:'يقرأ ملفات السيرفر',fix:'منع ../'}); logs.push('✓ LFI مكشوف');} else logs.push('× LFI نظيف');

    // 6-11 Security Headers
    let base=await get(target); let h={}; base.r.headers.forEach((v,k)=>h[k]=v);
    if(!h['x-frame-options']){add({risk:'medium',name:'Clickjacking - X-Frame-Options مفقود',location:target,payload:'header',evidence:'مفقود',desc:'يخلي موقعك ينحط داخل iframe',fix:'SAMEORIGIN'});}
    if(!h['x-content-type-options']){add({risk:'low',name:'MIME Sniffing',location:target,payload:'X-Content-Type',evidence:'مفقود',desc:'',fix:'nosniff'});}
    if(!h['content-security-policy']){add({risk:'low',name:'CSP مفقود',location:target,payload:'CSP',evidence:'مفقود',desc:'',fix:'اضف CSP'});}
    if(!h['strict-transport-security'] && target.startsWith('https')){add({risk:'low',name:'HSTS مفقود',location:target,payload:'HSTS',evidence:'مفقود',desc:'',fix:'اضف HSTS'});}
    if(h['server']){add({risk:'low',name:'كشف معلومات السيرفر',location:target,payload:h['server'],evidence:h['server'],desc:`السيرفر ${h['server']}`,fix:'اخفي Server header'});}
    if(h['x-powered-by']){add({risk:'low',name:'كشف لغة البرمجة',location:target,payload:h['x-powered-by'],evidence:h['x-powered-by'],desc:'',fix:'اخفي X-Powered-By'});}
    
    // 12 Cloudflare / WAF
    if(h['cf-ray']||h['server']?.toLowerCase().includes('cloudflare')) logs.push('السيرفر محمي Cloudflare'); else logs.push('بدون Cloudflare');

    if(score<0) score=0;
    let label=score<40?'🔴 خطير جدا - '+score+'/100':score<75?'🟠 متوسط - '+score:'/100':'🟢 آمن - '+score+'/100';
    logs.push(`انتهى الفحص - 12 فحص حقيقي - النتيجة ${score}`);
    return res.json({score,label,color:score<40?'critical':score<75?'high':'low',target,logs,findings,totalChecks:12,owasp:'A03:2021',cwe:'CWE-89'});
  }catch(e){return res.json({score:0,label:'خطأ '+e.message,color:'critical',logs:[e.message],findings:[]});}
                                                                                                                                                     }
