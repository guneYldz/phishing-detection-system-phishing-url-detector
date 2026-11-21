# PhishGuard AI - Kimlik Avı (Phishing) URL Tespit Sistemi
# Fırat Üniversitesi Bilgisayar Mühendisliği Tasarım Dersi Projesi (7. Hafta - Docker Konteynerizasyon)

FROM python:3.11-slim

LABEL maintainer="Murat Sayım, Güney Yıldız, Mehmet Tunahan Uzun"
LABEL description="PhishGuard AI - XGBoost ve Leksikal Özellik Çıkarımı Tabanlı Gerçek Zamanlı URL Analiz Servisi"
LABEL version="0.7.0"

# Python çalışma zamanı ve servis ortam değişkenleri
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    HOST=0.0.0.0 \
    PORT=8000 \
    MAX_BATCH_URLS=100 \
    SLA_MAX_LATENCY_MS=100.0

WORKDIR /app

# Bağımlılıkları önbellekleme avantajıyla kur
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Çalışma zamanında gerekli uygulama katmanlarını kopyala (.dockerignore ile ham veri seti hariç tutulur)
COPY features/ ./features/
COPY models/ ./models/
COPY frontend/ ./frontend/
COPY api/ ./api/

# Güvenlik için root olmayan uygulama kullanıcısı oluştur
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Konteyner sağlık kontrolü (/api/health uç noktası üzerinden model ve servis kontrolü)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, json, sys; res = json.loads(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).read().decode()); sys.exit(0 if res.get('status') == 'ok' and res.get('model_loaded') else 1)"

# FastAPI / Uvicorn sunucusunu başlat
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
