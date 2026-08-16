# Threat Intelligence Platform

**Threat Intelligence Platform** IP ünvanlarının, domenlərin və URL-lərin analizini həyata keçirən, risk səviyyəsini qiymətləndirən və nəticələri təhlükəsizlik paneli vasitəsilə təqdim edən Flask əsaslı veb tətbiqidir.

Layihənin əsas məqsədi kibertəhdidlərin aşkarlanması, qiymətləndirilməsi və idarə olunması prosesini sadələşdirmək, təhlükəsizlik analitiklərinə daha sürətli qərar verməyə kömək etməkdir.

---

# Əsas imkanlar

## İstifadəçi sistemi

* Qeydiyyat
* Giriş və çıxış
* Təhlükəsiz parol şifrələnməsi
* Flask-Login ilə sessiya idarəetməsi

## Təhdid analizi

Platforma aşağıdakı obyektləri analiz edə bilir:

* IP ünvanları
* Domenlər
* URL-lər

Analiz zamanı sistem:

* Məlumatın düzgünlüyünü yoxlayır
* Risk balını hesablayır
* Təhlükə səviyyəsini müəyyən edir
* Təhlükə kateqoriyalarını göstərir
* Təhlükəsizlik tövsiyəsi təqdim edir

---

# Risk qiymətləndirmə sistemi

Hər analiz üçün **0–100** arası risk balı hesablanır.

| Risk balı    | Təhlükə səviyyəsi  | Tövsiyə                          |
| ------------ | ------------------ | -------------------------------- |
| **0 – 30**   | **Təhlükə yoxdur** | **Heç bir tədbir tələb olunmur** |
| **31 – 70**  | **Şübhəli**        | **Nəzarətdə saxlayın**           |
| **71 – 100** | **Zərərli**        | **Dərhal bloklayın**             |

---

# Dashboard

Dashboard istifadəçiyə aşağıdakı məlumatları təqdim edir:

* Ümumi analiz statistikası
* Risk bölgüsü
* Təhdid kateqoriyaları
* Son analizlər
* Qrafik və diaqramlar

---

# Hesabatlar

Platforma aşağıdakı hesabat imkanlarını dəstəkləyir:

* Analiz tarixçəsinin saxlanılması
* CSV formatında ixrac
* PDF formatında hesabatların yaradılması

---

# REST API

### Təhdid analizi

```http
POST /api/analyze
```

### Dashboard statistikası

```http
GET /api/dashboard/summary
```

---

# İstifadə olunan texnologiyalar

| Sahə              | Texnologiyalar                       |
| ----------------- | ------------------------------------ |
| Backend           | Python, Flask                        |
| Verilənlər bazası | SQLite, SQLAlchemy                   |
| Autentifikasiya   | Flask-Login                          |
| Frontend          | HTML5, CSS3, Bootstrap 5, JavaScript |
| Qrafiklər         | Chart.js                             |
| Konfiqurasiya     | python-dotenv                        |

---

# Quraşdırma

Repository-ni klonlayın:

```bash
git clone https://github.com/hajieew/threat-intelligence-platform.git
cd threat-intelligence-platform
```

Virtual mühit yaradın:

```bash
python -m venv .venv
```

### Windows

```bash
.venv\Scripts\activate
```

### Linux/macOS

```bash
source .venv/bin/activate
```

Kitabxanaları quraşdırın:

```bash
pip install -r requirements.txt
```

---

# Layihənin işə salınması

```bash
python run.py
```

və ya

```bash
flask --app app.main:create_app run --debug
```

Brauzerdə açın:

```text
http://127.0.0.1:5000
```

---

# Verilənlər bazası

Layihə **SQLite** verilənlər bazasından istifadə edir.

`database.db` faylı proqram ilk dəfə işə salındıqda avtomatik yaradılır.

---

# Layihə strukturu

```text
threat-intelligence-platform/
│
├── app/
│   ├── auth/
│   ├── database/
│   ├── models/
│   ├── routes/
│   ├── services/
│   ├── static/
│   ├── templates/
│   ├── utils/
│   └── main.py
│
├── requirements.txt
├── run.py
├── .env
└── README.md
```

---

# Nümunə analizlər

| Giriş           | Gözlənilən nəticə |
| --------------- | ----------------- |
| google.com      | Təhlükə yoxdur    |
| 8.8.8.8         | Təhlükə yoxdur    |
| 185.199.108.153 | Zərərli           |

---

# Gələcək inkişaf planları

Layihənin növbəti versiyalarında aşağıdakı funksiyaların əlavə olunması planlaşdırılır:

* OpenCTI inteqrasiyası
* VirusTotal inteqrasiyası
* AbuseIPDB inteqrasiyası
* Threat Intelligence Feed-ləri
* IOC Enrichment
* STIX 2.1 dəstəyi
* Brend təqlidinin (Brand Impersonation) aşkarlanması
* Watchlist sistemi
* E-mail bildirişləri
* Süni intellekt əsaslı risk qiymətləndirilməsi
* Role-Based Access Control (RBAC)
* SIEM və EDR sistemləri ilə inteqrasiya
* Azərbaycan bazarı üçün lokal risk qiymətləndirmə modeli
* Azərbaycan dilində avtomatik hesabatların hazırlanması

---

# Layihənin məqsədi

Threat Intelligence Platform kibertəhdidlərin aşkarlanması, qiymətləndirilməsi və idarə olunması üçün hazırlanmış veb tətbiqidir. Layihənin uzunmüddətli məqsədi beynəlxalq Threat Intelligence yanaşmalarını Azərbaycan bazarına uyğunlaşdırmaq, lokal risk qiymətləndirmə modeli yaratmaq və gələcəkdə OpenCTI əsaslı genişləndirilə bilən Cyber Threat Intelligence platformasına çevrilməkdir.

---

   - **Email:** `123@holbertonstudents.com`
   - **Password:** `Holbie123!`
