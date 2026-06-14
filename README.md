# SENSITIVE DATA EXPOSURE DEMO

Bu demo şu akışı gösterir:

1. Şifreyi düz metin saklama
2. Salt olmadan hashleme - SHA-256 algoritması
3. Salt ile hashleme - bcrypt algoritması
4. Hashing ile geri okunamaz veri saklama
5. Encryption ile geri okunabilir veri saklama

## Önemli not

SHA-256 genel amaçlı bir hash algoritmasıdır. Salt'ı otomatik üretmez. Bu nedenle demo'da "salt olmadan hashleme" farkını göstermek için kullanılır.

bcrypt ise parola saklama için tasarlanmış bir algoritmadır. Her kayıt için salt üretir ve salt bilgisini hash formatının içinde saklar.

## Kurulum

```bash
cd security_demo_v5
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Tarayıcıda aç:

```text
http://127.0.0.1:5000
```
