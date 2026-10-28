# Kimlik Avı (Phishing) URL Tespit Sistemi

Fırat Üniversitesi Bilgisayar Mühendisliği Tasarım Dersi Projesi

Bu proje, şüpheli web sitelerinin URL adreslerini leksikal ve sezgisel nitelikler üzerinden analiz ederek zararlı (phishing) veya güvenli (benign) olduğunu tespit eden makine öğrenmesi tabanlı bir güvenlik sistemidir.

## Proje Ekibi
- Murat Sayım (235260073)
- Güney Yıldız (245260019)
- Mehmet Tunahan Uzun (235260025)

---

## Proje Yapısı ve İşleyiş

Sistem dört ana aşamadan oluşmaktadır:

1. **Veri Toplama ve Temizleme:**
   - PhishTank ve OpenPhish beslemelerinden 50.000 zararlı URL, Tranco Top 1M listesinden 50.000 güvenli URL çekilerek toplam 100.000 satırlık dengeli veri seti (`dataset.csv`) oluşturulmuştur.
   - Çakışan kayıtlar tekilleştirilmiş, etiket çelişkileri temizlenmiştir.

2. **Leksikal ve Sezgisel Özellik Çıkarımı:**
   - Harici ağ sorgularına bağlı kalmadan, URL başına milisaniyenin altında (<0.5 ms) çalışan 26 leksikal parametre çıkarılmaktadır (`features/extract_features.py`).
   - Çıkarılan nitelikler: URL/domain/path/query uzunlukları, özel karakter sayıları (`.`, `-`, `_`, `/`, `?`, `=`, `@`, `%`, `&`), rakam/harf oranları, IP adresi kullanımı, HTTPS kullanımı, alt alan adı sayısı, domain içi tire kullanımı, şüpheli anahtar kelimeler, marka taklidi kontrolü ve Shannon karakter entropisi.

3. **Sınıflandırma ve Model Doğrulama:**
   - Veri seti %80 eğitim (80.000) ve %20 test (20.000) olarak ayrılmıştır.
   - XGBoost ve Random Forest algoritmaları eğitilmiş; test kümesi üzerinde doğruluk, duyarlılık, hassasiyet, F1 skoru ve yanlış pozitif oranları (FPR) hesaplanmıştır.

4. **FastAPI REST API Arka Uç Servisi:**
   - Eğitilen nihai XGBoost modelini (`models/xgboost_model.joblib`) başlangıçta belleğe (RAM) yükleyen ve `/api/analyze` uç noktası üzerinden tekil URL sorgulamalarını ortalama **1.42 ms** içinde yanıtlayan FastAPI arka ucu (`api/main.py`) geliştirilmiştir.
   - Her sorgu için olasılık skoru (`phishing_probability`), sınıf etiketi ve açıklanabilir leksikal risk faktörleri (`risk_factors`) JSON olarak üretilmektedir.

---

## Model Test Sonuçları (20.000 Test Örneği)

| Model | Doğruluk (Accuracy) | Hassasiyet (Precision) | Duyarlılık (Recall) | F1-Skoru | Yanlış Pozitif Oranı (FPR) | Ortalama Tahmin Süresi |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **XGBoost** | **%97.67** | **%98.89** | **%96.42** | **%97.64** | **%1.08** | **0.0010 ms / URL** |
| Random Forest | %97.64 | %98.88 | %96.36 | %97.60 | %1.09 | 0.0021 ms / URL |

- **XGBoost Karışıklık Matrisi:**
  - Doğru Negatif (TN): 9.892
  - Yanlış Pozitif (FP): 108
  - Yanlış Negatif (FN): 358
  - Doğru Pozitif (TP): 9.642

---

## Kurulum ve Çalıştırma

### Gereksinimlerin Yüklenmesi
```bash
pip install -r requirements.txt
```

### 1. Özellik Çıkarımını Test Etme
```bash
python features/extract_features.py
```

### 2. Modelleri Eğitme ve Değerlendirme
```bash
python models/train_models.py
```

### 3. FastAPI REST API Arka Ucunu Başlatma
```bash
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Swagger OpenAPI Arayüzü:** `http://127.0.0.1:8000/docs`
- **API Doğrulama Testleri:** `python api/test_api.py`

---

## Dizin Yapısı

```
phishing-detection-system/
├── api/
│   ├── __init__.py
│   ├── main.py                       # FastAPI REST API arka uç servisi
│   └── test_api.py                   # REST API uç nokta ve gecikme (<100 ms) doğrulama testleri
├── features/
│   └── extract_features.py           # 26 adet leksikal ve sezgisel özellik çıkarım motoru
├── models/
│   ├── train_models.py               # XGBoost ve Random Forest eğitim/değerlendirme betiği
│   ├── xgboost_model.json            # Eğitilmiş model (JSON)
│   ├── xgboost_model.joblib          # Eğitilmiş model (Joblib)
│   ├── feature_names.joblib          # Özellik listesi
│   ├── model_evaluation_results.json # Ham metrik sonuçları
│   └── api_benchmark_results.json    # REST API gecikme ve doğrulama sonuçları
├── veriseti/
│   ├── dataset.csv                   # 100.000 satırlık dengeli veri seti
│   ├── features_100k.csv             # Özellik çıkarılmış veri seti matrisi
│   ├── benign_urls.csv               # Tranco kaynaklı 50.000 güvenli URL
│   ├── phishing_urls.csv             # PhishTank/OpenPhish kaynaklı 50.000 zararlı URL
│   ├── create_dataset.py             # Veri seti birleştirme ve karıştırma
│   ├── extract_benign.py             # Tranco listesinden güvenli URL ayıklama
│   └── extract_phishing.py           # Açık beslemelerden phishing URL ayıklama
├── requirements.txt                  # Bağımlılıklar
└── README.md
```
