# 👾 HUNTER v6 — Autonomous Security Verification Agent

> وكيل أمني ذاتي لاكتشاف وتحليل والتحقق من مؤشرات ثغرات الويب ضمن نطاقات مصرّح بها.

HUNTER v6 ليس مجرد scanner يضع علامة `vulnerable=true`.
الوكيل يبني فرضية، يجمع Evidence، يطلب تحققًا آمنًا، يراجع النتيجة عبر Critic مستقل، ثم يصنفها:

`CANDIDATE → VERIFYING → LIKELY / CONFIRMED / INCONCLUSIVE / FALSE_POSITIVE`

## لماذا v6؟

- 🤖 Agentic planner
- 🔎 Recon + crawling
- 📜 JavaScript analysis
- 🧠 Central Knowledge Base
- 🧪 Evidence-first verification
- ⚖️ Deterministic Decision Engine
- 🧐 Independent Critic
- 🔁 Re-verification loop
- 📊 Confidence + score
- 🛡️ Strict ScopeGuard
- 📑 HTML + JSON reports
- 🧪 Automated tests
- 🔌 OpenAI-compatible LLM providers

## المعمارية

```text
Target
  ↓
ScopeGuard
  ↓
Recon
  ├─ Subdomains
  ├─ Crawler
  └─ Wayback
  ↓
Analysis
  ├─ Headers
  ├─ Cookies
  ├─ Sensitive paths
  └─ JavaScript
  ↓
Candidate Findings
  ↓
AI Planner / Deterministic Planner
  ↓
Verification Engine
  ↓
Evidence
  ↓
Decision Engine
  ↓
Critic
  ↓
CONFIRMED / LIKELY / INCONCLUSIVE / FALSE POSITIVE
  ↓
HTML + JSON
```

## التثبيت

```bash
git clone https://github.com/Mamduh-911/Hunter.git
cd Hunter

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## التشغيل

```bash
python3 hunter.py -u https://target.example --authorized
```

أو:

```bash
python3 hunter.py
```

ثم أدخل الهدف وأكد التصريح.

### بدون تحقق نشط

```bash
python3 hunter.py -u https://target.example --authorized --no-verify
```

### بدون Burp

```bash
python3 hunter.py -u https://target.example --authorized --no-proxy
```

### تشغيل بدون LLM

```bash
python3 hunter.py -u https://target.example --authorized --no-llm
```

الوضع بدون LLM ما يزال يستخدم Decision Engine وVerification Engine.

## LLM

أي مزود متوافق مع OpenAI Chat Completions API يمكن استخدامه.

### Kimi

```bash
export HUNTER_LLM_BASE_URL="https://api.moonshot.ai/v1"
export HUNTER_LLM_API_KEY="YOUR_KEY"
export HUNTER_LLM_MODEL="kimi-k2-0711-preview"
```

### OpenAI

```bash
export HUNTER_LLM_BASE_URL="https://api.openai.com/v1"
export HUNTER_LLM_API_KEY="YOUR_KEY"
export HUNTER_LLM_MODEL="gpt-4o"
```

### Ollama

```bash
export HUNTER_LLM_BASE_URL="http://localhost:11434/v1"
export HUNTER_LLM_API_KEY="ollama"
export HUNTER_LLM_MODEL="qwen2.5:3b"
```

ثم:

```bash
python3 hunter.py -u https://target.example --authorized
```

## Verification

التحقق النشط في الإصدار الحالي مصمم ليكون غير مدمّر:

- XSS: inert canary/reflection check
- SQLi: differential error check
- Open Redirect: neutral `example.com` redirect check
- CORS: controlled Origin reflection check

لا يتم تنفيذ JavaScript محقون، ولا تعديل أو حذف بيانات.

## Evidence

كل Finding يمكن أن يحتوي:

```text
Evidence
├── kind
├── description
├── strength
├── observed
└── timestamp
```

ولا يمكن للـ LLM وحده تحويل Finding إلى `CONFIRMED`.

## التقارير

بعد الفحص:

```text
hunter_reports/
├── hunter_dashboard.html
├── findings.json
└── hunter_targets.txt
```

افتح:

```bash
firefox hunter_reports/hunter_dashboard.html
```

## الاختبارات

```bash
pytest -q
```

## أدوات خارجية اختيارية

إذا كانت مثبتة، يمكن لـ HUNTER الاستفادة من:

- `subfinder`
- `assetfinder`
- `waybackurls`

لكن الأداة الأساسية لا تعتمد عليها كي تعمل.

## المسؤولية

استخدم HUNTER فقط على الأنظمة التي تملك تصريحًا لاختبارها، مثل بيئاتك الخاصة أو برامج Bug Bounty التي تسمح بهذا النوع من الاختبار. المستخدم مسؤول عن الالتزام بنطاق البرنامج وسياساته.
