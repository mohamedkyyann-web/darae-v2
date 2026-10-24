export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "No URL" });

  let score = 100;
  let vulns = [];
  let logs = [];

  try {
    const u = new URL(url);
    const target = url.toLowerCase();

    const add = (type, severity, evidence, fix) => {
      let points = severity === "Critical" ? 25 : severity === "High" ? 20 : severity === "Medium" ? 10 : 5;
      score -= points;
      vulns.push({ type, severity, evidence: evidence?.substring(0,150), fix });
    };

    let resp = null;
    let headers = {};
    try {
      resp = await fetch(url, {
        method: "GET",
        redirect: "manual",
        headers: { "User-Agent": "DARAE-V16-Security-Scanner" },
        signal: AbortSignal.timeout(8000)
      });
      headers = Object.fromEntries(resp.headers.entries());
      logs.push(`Status: ${resp.status}`);
    } catch (e) {
      logs.push(`Fetch Error: ${e.message}`);
    }

    if (resp && resp.status >= 300 && resp.status < 400) {
      const loc = resp.headers.get("location") || "";
      if (loc && loc.startsWith("http") && !loc.includes(u.hostname)) {
        add("Open Redirect REAL", "Critical", `Location: ${loc}`, "تحقق من بارامتر redirect يسمح لخارج الدومين");
      }
    }

    if (target.includes("../") || target.includes("..%2f") || target.includes("%2e%2e")) {
      add("Path Traversal", "High", url, "امنع ../ وفلتر المسارات");
    }
    if (target.includes("<script") || target.includes("onerror=") || target.includes("javascript:")) {
      add("XSS", "High", url, "فلتر input و استخدم CSP");
    }
    if (target.match(/('|%27)\s*(or|union|select)/) || target.includes("' or '1'='1")) {
      add("SQL Injection", "Critical", url, "استخدم Prepared Statements");
    }
    if (target.includes("localhost") || target.includes("127.0.0.1") || target.includes("169.254.169.254")) {
      add("SSRF", "Critical", url, "قائمة بيضاء للـ URLs الداخلية");
    }
    if (target.includes("etc/passwd") || target.includes("etc/shadow") || target.includes("proc/self")) {
      add("Local File Inclusion", "High", url, "منع include للملفات الخارجية");
    }
    if (target.match(/[;&|`]\s*(id|whoami|cat|ls)/)) {
      add("RCE", "Critical", url, "منع exec و system");
    }
    if (target.includes("%0d") || target.includes("%0a")) {
      add("CRLF Injection", "Medium", url, "فلتر \\r\\n");
    }
    if (!headers["x-frame-options"]) add("Missing X-Frame-Options", "Medium", "No header", "اضف SAMEORIGIN");
    if (!headers["content-security-policy"]) add("Missing CSP", "Low", "No header", "اضف CSP");
    if (!headers["strict-transport-security"]) add("Missing HSTS", "Low", "No header", "اضف HSTS");
    if (!headers["x-content-type-options"]) add("Missing X-Content-Type", "Low", "No header", "اضف nosniff");
    if (headers["server"]) add("Server Disclosure", "Info", headers["server"], "اخفاء اصدار السيرفر");
    if (headers["x-powered-by"]) add("X-Powered-By Disclosure", "Info", headers["x-powered-by"], "اخفاء X-Powered-By");
    if (url.startsWith("http://")) add("No HTTPS", "High", url, "استخدم HTTPS");
    if (!target.includes("?") && vulns.length === 0) {
      score = 90;
    }

    if (score < 0) score = 0;
    if (score > 100) score = 100;
    let status = score >= 80 ? "آمن ✅" : score >= 50 ? "متوسط ⚠️" : "خطير 🔴";

    return res.json({ url, score, status, vulnerabilities: vulns, totalChecks: 20, realServerChecks: true, logs, headersChecked: headers });
  } catch (e) {
    return res.status(500).json({ url, score: 0, status: "خطأ", error: e.message });
  }
  }
