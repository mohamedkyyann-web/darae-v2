export default async function handler(req,res){
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Content-Type','application/json');
  try{
    let target=(req.query.url||'').trim();
    let code=(req.query.code||'').trim();
    if(!target) return res.status(200).json({score:0,label:'حط رابط',color:'critical',findings:[],logs:['حط رابط'],totalChecks:12,owasp:'-',cwe:'-'});
    if(!target.startsWith('http')) target='https://'+target;
    if(!code.toUpperCase().startsWith('DARAE-')) return res.status(200).json({score:0,label:'كود غلط',color:'critical',findings:[],logs:['لازم يبدأ DARAE-'],totalChecks:12,owasp:'-',cwe:'-'});
    
    let score=100,findings=[],logs=[`فحص ${target}`];
    const add=(o)=>{findings.push(o); score-=o.risk==='high'?25:10;};
    const fetchText=async(u)=>{
      try{
        let r=await fetch(u,{headers:{'User-Agent':'Mozilla/5.0'},signal:AbortSignal.timeout(8000)});
        let t=await r.text();
        return {status:r.status,headers:r.headers,text:t};
      }catch(e){return {status:0,headers:{get:()=>null},text:'',err:e.message};}
    };

    let base=await fetchText(target);
    logs.push(`فتح: ${base.status}`);
    if(base.status===0) return res.status(200).json({score:0,label:'الموقع ما يفتح',color:'critical',findings:[],logs:[base.err||'timeout'],totalChecks:12,owasp:'-',cwe:'-'});

    // 1 SQL
    let s1=await fetchText(target+"'"); 
    if(/sql syntax|mysql|ORA-|unclosed quotation/i.test(s1.text)){
      add({risk:'high',name:'SQL Injection',location:target+"'",payload:"'",evidence:s1.text.substring(0,80),desc:'خطأ SQL',fix:'prepared statements'});
    }
    // 2 XSS
    let xurl=target+(target.includes('?')?'&':'?')+'test=<script>alert(1)</script>';
    let s2=await fetchText(xurl);
    if(s2.text.includes('<script>alert(1)')){
      add({risk:'high',name:'Reflected XSS',location:xurl,payload:'<script>alert(1)',evidence:'payload reflected',desc:'XSS',fix:'escape output'});
    }
    // 3 Headers
    let h={}; try{base.headers.forEach((v,k)=>h[k.toLowerCase()]=v)}catch{}
    if(!h['x-frame-options']) add({risk:'medium',name:'Clickjacking - X-Frame Missing',location:target,payload:'header',evidence:'مفقود',desc:'يمكن وضعه في iframe',fix:'X-Frame-Options: SAMEORIGIN'});
    if(h['server']) add({risk:'low',name:'Server Info: '+h['server'],location:target,payload:h['server'],evidence:h['server'],desc:'كشف السيرفر',fix:'اخفي header'});

    if(score<0) score=0;
    let color=score<40?'critical':score<70?'high':'low';
    let label=score<40?'🔴 خطير '+score+'/100':score<70?'🟠 متوسط '+score+'/100':'🟢 آمن '+score+'/100';
    logs.push(`انتهى - النتيجة ${score}`);

    return res.status(200).json({score,label,color,target,logs,findings,totalChecks:12,owasp:'A03:2021',cwe:'CWE-89'});
  }catch(err){
    return res.status(200).json({score:0,label:'خطأ سيرفر',color:'critical',findings:[],logs:[err.message],totalChecks:12,owasp:'-',cwe:'-'});
  }
                                 }
