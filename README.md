# 👾 HUNTER v4.2 - أداة صيد الثغرات الاحترافية المتكاملة

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-red)
![Version](https://img.shields.io/badge/Version-v4.2-orange)
![License](https://img.shields.io/badge/License-MIT-green)

**HUNTER**
 هي أداة مفتوحة المصدر مطورة بلغة بايثون، تهدف إلى مساعدة الباحثين الأمنيين ومختبري الاختراق في إجراء عمليات الاستكشاف الأمني، وتحليل تطبيقات الويب، وجمع المعلومات، واكتشاف المؤشراتالمحتملة للثغرات بأساليب آمنة وغير مؤثرة على الأنظمة، مع التركيز على الكشف والتحليل دون تنفيذ أي استغلال آلي
> ⚠️ **الأداة مخصصة للاستكشاف والكشف فقط، ولا تقوم بتنفيذ عمليات استغلال تلقائية.**

---

# ✨ المميزات

- 🌐 استكشاف مواقع الويب
- 🔍 تحليل ملفات JavaScript
- 🗺️ اكتشاف وتحليل ملفات Source Map
- 🔑 اكتشاف المفاتيح والتوكنات المسربة
- 📡 استخراج الروابط وواجهات API المخفية
- 📂 البحث عن الملفات الحساسة المكشوفة
- 🍪 تحليل إعدادات Cookies
- 🛡️ فحص رؤوس الحماية (Security Headers)
- 📄 التعرف على التقنيات المستخدمة بالموقع
- 🌍 جمع النطاقات الفرعية
- 📚 جمع روابط Wayback Machine
- 📋 إنشاء تقارير HTML تفاعلية
- 🎯 التكامل مع Burp Suite
- ⚡ وضع الفحص السريع (Rapid)
- 🚀 وضع الفحص الشامل (Comprehensive)

---

# 📥 التثبيت (Installation)

## استنساخ المستودع

```bash
git clone https://github.com/Mamduh-911/Hunter.git
cd Hunter
python3 hunter.py
https://example.com
y/n
y
```

## تثبيت المتطلبات

```bash
pip3 install -r requirements.txt
```

## الأدوات الموصى بها

للحصول على أفضل نتائج أثناء الاستكشاف، يُفضل تثبيت الأدوات التالية وإضافتها إلى متغيرات النظام (PATH):

- subfinder
- assetfinder
- waybackurls

---

# 🚀 طريقة الاستخدام

## التشغيل التفاعلي

```bash
python3 hunter.py
```

## فحص سريع

```bash
python3 hunter.py -u https://example.com -t rapid
```

## فحص شامل

```bash
python3 hunter.py -u https://example.com -t comprehensive
```

## تعطيل بروكسي Burp Suite

```bash
python3 hunter.py -u https://example.com --no-proxy
```

## استخدام بروكسي مخصص

```bash
python3 hunter.py -u https://example.com --proxy http://127.0.0.1:8080
```

---

# 📊 الملفات الناتجة

بعد انتهاء الفحص، تقوم الأداة بإنشاء مجلد باسم:

```
hunter_reports/
```

ويحتوي على:

```
hunter_reports/
├── hunter_dashboard.html
├── hunter_burp_targets.txt
├── findings.json
└── logs.txt
```

## 📄 hunter_dashboard.html

لوحة تحكم تفاعلية تعرض:

- نتائج الفحص
- تحليل JavaScript
- ملفات Source Map
- رؤوس الحماية
- إعدادات Cookies
- الملفات الحساسة
- التقنيات المستخدمة
- الروابط المخفية
- النتائج المصنفة حسب الخطورة

## 🎯 hunter_burp_targets.txt

قائمة بجميع الروابط المكتشفة لتسهيل إعادة اختبارها يدويًا باستخدام Burp Suite.

## 📋 findings.json

ملف JSON يحتوي على جميع النتائج لتسهيل معالجتها أو استخدامها في أدوات أخرى.

## 📝 logs.txt

سجل كامل لعملية الفحص.

---

# 🔍 ما الذي تقوم الأداة باكتشافه؟

- JavaScript Secrets
- API Keys
- JWT Tokens
- Bearer Tokens
- Hidden API Endpoints
- Source Maps
- Hidden Routes
- GraphQL Endpoints
- Swagger / OpenAPI
- WebSocket URLs
- Firebase Configurations
- AWS Keys
- Google API Keys
- Stripe Keys
- GitHub Tokens
- Cloud Storage References
- الملفات الحساسة المكشوفة
- ملفات النسخ الاحتياطية
- ملفات الإعدادات
- Cookie Misconfigurations
- Missing Security Headers
- Technology Fingerprinting
- Subdomains
- Wayback URLs

---

# 🛡️ التكامل مع Burp Suite

تقوم الأداة بتمرير جميع الطلبات عبر Burp Suite بشكل افتراضي.

البروكسي الافتراضي:

```
127.0.0.1:8080
```

لتعطيل البروكسي:

```bash
python3 hunter.py --no-proxy
```

أو استخدام بروكسي آخر:

```bash
python3 hunter.py --proxy http://IP:PORT
```

---

# 📋 المتطلبات

- Python 3.10 أو أحدث
- requests
- urllib3

ويُنصح أيضًا بتثبيت:

- subfinder
- assetfinder
- waybackurls

---

# ⚠️ إخلاء المسؤولية

تم تطوير **HUNTER** لأغراض تعليمية وللاستخدام في الاختبارات الأمنية المصرح بها وبرامج **Bug Bounty** فقط.

لا تقوم الأداة بتنفيذ عمليات استغلال تلقائية، وإنما تركز على **جمع المعلومات، والتحليل، والكشف عن المؤشرات الأمنية** لمساعدة الباحث في التحقق اليدوي.

يتحمل المستخدم كامل المسؤولية عن استخدام الأداة، ويجب التأكد من وجود تصريح قانوني قبل إجراء أي فحص على أي نظام أو موقع.

لا يتحمل مطور الأداة أي مسؤولية عن أي استخدام غير قانوني أو مخالف للأنظمة أو سياسات برامج مكافآت الثغرات.

---

# 🤝 المساهمة

نرحب بجميع المساهمات التي تساعد في تطوير الأداة وتحسينها.

يمكنك فتح:

- Issue
- Pull Request
- Feature Request

---

# ⭐ دعم المشروع

إذا أعجبتك الأداة ووجدتها مفيدة، لا تنسَ وضع ⭐ للمستودع على GitHub لدعم استمرار تطويرها.
