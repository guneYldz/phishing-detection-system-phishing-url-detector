"""
Phishing URL Tespit Sistemi - FastAPI Servisi (v0.7.0 - Docker & Production Ready)
XGBoost modelini belleğe yükler, tekil ve toplu URL analizi uç noktaları ile web arayüzünü sunar.
"""

import os
import sys
import json
import time
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple

import joblib
import pandas as pd
import xgboost as xgb
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from features.extract_features import extract_url_features

API_VERSION = "0.7.0"
APP_ENV = os.getenv("APP_ENV", "production")
MAX_BATCH_URLS = int(os.getenv("MAX_BATCH_URLS", "100"))
SLA_MAX_LATENCY_MS = float(os.getenv("SLA_MAX_LATENCY_MS", "100.0"))
SERVICE_START_TIME = time.time()

ACTIVE_ENDPOINTS = [
    "/",
    "/ui",
    "/api",
    "/api/health",
    "/api/model-info",
    "/api/analyze",
    "/api/batch-analyze",
]

app = FastAPI(
    title="PhishGuard AI - Kimlik Avı URL Tespit Sistemi",
    description="XGBoost ve leksikal özellik çıkarımı tabanlı konteyner uyumlu URL analiz servisi",
    version=API_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
XGB_JOBLIB_PATH = os.path.join(MODELS_DIR, "xgboost_model.joblib")
XGB_JSON_PATH = os.path.join(MODELS_DIR, "xgboost_model.json")
FEATURE_NAMES_PATH = os.path.join(MODELS_DIR, "feature_names.joblib")
EVAL_RESULTS_PATH = os.path.join(MODELS_DIR, "model_evaluation_results.json")
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
FRONTEND_HTML_PATH = os.path.join(FRONTEND_DIR, "index.html")

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

MODEL = None
FEATURE_NAMES: List[str] = []
MODEL_METRICS: Dict[str, Any] = {}


def load_artifacts() -> None:
    """Eğitilmiş XGBoost modelini, özellik listesini ve test metriklerini yükler."""
    global MODEL, FEATURE_NAMES, MODEL_METRICS

    if os.path.exists(FEATURE_NAMES_PATH):
        FEATURE_NAMES = joblib.load(FEATURE_NAMES_PATH)
    else:
        sample_feats = extract_url_features("https://www.google.com")
        FEATURE_NAMES = list(sample_feats.keys())

    if os.path.exists(XGB_JOBLIB_PATH):
        MODEL = joblib.load(XGB_JOBLIB_PATH)
    elif os.path.exists(XGB_JSON_PATH):
        clf = xgb.XGBClassifier()
        clf.load_model(XGB_JSON_PATH)
        MODEL = clf
    else:
        raise FileNotFoundError(f"Eğitilmiş model dosyası bulunamadı: {XGB_JOBLIB_PATH}")

    if os.path.exists(EVAL_RESULTS_PATH):
        with open(EVAL_RESULTS_PATH, "r", encoding="utf-8") as f:
            MODEL_METRICS = json.load(f)


def read_frontend_html() -> str:
    """Web arayüzü HTML dosyasını okur."""
    if not os.path.exists(FRONTEND_HTML_PATH):
        raise HTTPException(status_code=404, detail="Web arayüzü dosyası bulunamadı.")

    with open(FRONTEND_HTML_PATH, "r", encoding="utf-8") as f:
        return f.read()


load_artifacts()


class URLAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=4096, description="Analiz edilecek URL")


class BatchURLAnalyzeRequest(BaseModel):
    urls: List[str] = Field(..., description="Toplu analiz edilecek URL listesi (en fazla 100)")


def generate_lexical_risk_factors(features: dict, phishing_prob: float) -> List[Dict[str, str]]:
    """Çıkarılan leksikal özelliklere göre okunabilir risk açıklamaları üretir."""
    findings = []

    if features.get("has_ip") == 1:
        findings.append({
            "severity": "high",
            "factor": "IP Adresi Kullanımı",
            "description": "Domain adı yerine doğrudan IPv4 adresi kullanılmış."
        })

    if features.get("brand_spoofing") == 1:
        findings.append({
            "severity": "high",
            "factor": "Marka Taklidi (Brand Spoofing)",
            "description": "URL içerisinde popüler bir marka adı geçiyor ancak ana domain bu markaya ait değil."
        })

    if features.get("tld_in_path_or_sub") == 1:
        findings.append({
            "severity": "high",
            "factor": "Subdomain veya Path İçinde Yanıltıcı TLD",
            "description": "Alt alan adı veya dizin yolunda yanıltıcı uzantı (.com, .net vb.) tespit edildi."
        })

    if features.get("num_at", 0) > 0:
        findings.append({
            "severity": "high",
            "factor": "'@' Sembolü Kullanımı",
            "description": "URL içinde kullanıcıyı farklı bir adrese yönlendirebilecek '@' karakteri mevcut."
        })

    if features.get("is_https") == 0:
        findings.append({
            "severity": "medium",
            "factor": "HTTPS Eksikliği",
            "description": "Bağlantı güvenli HTTPS şeması kullanmıyor."
        })

    if features.get("has_action_keywords") == 1:
        findings.append({
            "severity": "medium",
            "factor": "Şüpheli Eylem Anahtar Kelimeleri",
            "description": "URL içinde 'login, verify, secure, account, update' gibi hassas anahtar kelimeler yer alıyor."
        })

    if features.get("prefix_suffix") == 1:
        findings.append({
            "severity": "medium",
            "factor": "Domain İçinde Tire (-) Kullanımı",
            "description": "Alan adında kimlik avı sitelerinde sıkça görülen tire (-) kullanımı tespit edildi."
        })

    if features.get("is_shortened") == 1:
        findings.append({
            "severity": "medium",
            "factor": "URL Kısaltma Servisi",
            "description": "Hedef adresi gizleyen bir URL kısaltma servisi kullanılmış."
        })

    if features.get("url_length", 0) > 75:
        findings.append({
            "severity": "medium",
            "factor": f"Uzun URL Yapısı ({features['url_length']} karakter)",
            "description": "URL uzunluğu standart güvenli sitelerin ortalamasının üzerinde."
        })

    if features.get("shannon_entropy", 0.0) >= 4.6:
        findings.append({
            "severity": "low",
            "factor": f"Yüksek Karakter Entropisi ({features['shannon_entropy']})",
            "description": "URL diziliminde rastgele karakter/rakam karmaşıklığı yüksek."
        })

    if not findings and phishing_prob < 0.5:
        findings.append({
            "severity": "safe",
            "factor": "Standart Leksikal Yapı",
            "description": "URL uzunluğu ve karakter dağılımı meşru sitelerle uyumlu."
        })

    return findings


SECOND_LEVEL_CCTLD = {"edu", "gov", "com", "org", "net", "ac", "co"}


def extract_features_for_model(url_clean: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Görünüm için ham URL özelliklerini, model tahmini için ise Tranco eğitim formatıyla
    (https://domain/) uyumlu normalize edilmiş özellikleri döndürür.
    """
    raw_features = extract_url_features(url_clean)
    has_red_flags = any(
        [
            raw_features.get("is_https") != 1,
            raw_features.get("has_ip") == 1,
            raw_features.get("brand_spoofing") == 1,
            raw_features.get("has_action_keywords") == 1,
            raw_features.get("prefix_suffix") == 1,
            raw_features.get("tld_in_path_or_sub") == 1,
            raw_features.get("has_double_slash_path") == 1,
            raw_features.get("is_shortened") == 1,
            raw_features.get("num_at", 0) > 0,
            raw_features.get("url_length", 0) > 120,
        ]
    )
    if has_red_flags:
        return raw_features, raw_features

    candidate = url_clean if "://" in url_clean else f"http://{url_clean}"
    hostname = urlparse(candidate).netloc.lower().split(":")[0]
    bare_host = hostname[4:] if hostname.startswith("www.") else hostname
    parts = [p for p in bare_host.split(".") if p]

    is_root_domain = len(parts) == 2 or (
        len(parts) == 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL_CCTLD
    )
    if is_root_domain:
        model_features = extract_url_features(f"https://{bare_host}/")
        return raw_features, model_features

    return raw_features, raw_features


def determine_risk_level(phishing_prob: float) -> str:
    if phishing_prob >= 0.85:
        return "KRİTİK"
    elif phishing_prob >= 0.50:
        return "YÜKSEK"
    elif phishing_prob >= 0.25:
        return "ORTA"
    return "DÜŞÜK (GÜVENLİ)"


def build_analysis_result(
    url_clean: str,
    features: Dict[str, Any],
    benign_prob: float,
    phishing_prob: float,
    latency_ms: float,
) -> Dict[str, Any]:
    """Tekil ve toplu URL analizleri için ortak sonuç sözlüğünü oluşturur."""
    pred_label = int(1 if phishing_prob >= 0.50 else 0)
    risk_factors = generate_lexical_risk_factors(features, phishing_prob)

    return {
        "url": url_clean,
        "prediction": pred_label,
        "label": "PHISHING" if pred_label == 1 else "BENIGN",
        "is_phishing": bool(pred_label == 1),
        "phishing_probability": round(phishing_prob, 4),
        "benign_probability": round(benign_prob, 4),
        "risk_level": determine_risk_level(phishing_prob),
        "latency_ms": round(latency_ms, 3),
        "meets_latency_sla": bool(latency_ms < SLA_MAX_LATENCY_MS),
        "risk_factors": risk_factors,
        "lexical_features": features,
    }


@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
@app.get("/ui/", response_class=HTMLResponse)
async def serve_frontend():
    """Web arayüzünü sunar."""
    return HTMLResponse(content=read_frontend_html(), status_code=200)


@app.get("/style.css")
@app.get("/ui/style.css")
async def serve_css():
    """Ön yüz CSS dosyasını sunar."""
    return FileResponse(os.path.join(FRONTEND_DIR, "style.css"), media_type="text/css")


@app.get("/app.js")
@app.get("/ui/app.js")
async def serve_js():
    """Ön yüz JavaScript dosyasını sunar."""
    return FileResponse(os.path.join(FRONTEND_DIR, "app.js"), media_type="application/javascript")


@app.get("/api")
async def api_root_status():
    """API servis bilgisini ve aktif uç noktaları döndürür."""
    return {
        "service": "PhishGuard AI URL Detection API",
        "version": API_VERSION,
        "environment": APP_ENV,
        "container_ready": True,
        "docs_url": "/docs",
        "ui_url": "/ui",
        "endpoints": ACTIVE_ENDPOINTS,
    }


@app.get("/api/health")
async def health_check():
    """Servisin, konteyner çalışma süresinin ve bellekteki modelin durumunu kontrol eder."""
    return {
        "status": "ok",
        "version": API_VERSION,
        "environment": APP_ENV,
        "container_ready": True,
        "model_loaded": MODEL is not None,
        "model_type": "XGBoost Classifier",
        "feature_count": len(FEATURE_NAMES),
        "max_batch_urls": MAX_BATCH_URLS,
        "sla_max_latency_ms": SLA_MAX_LATENCY_MS,
        "uptime_seconds": round(time.time() - SERVICE_START_TIME, 2),
    }


@app.get("/api/model-info")
async def get_model_info():
    """Eğitilen modellerin doğrulama metriklerini ve özellik listesini döndürür."""
    return {
        "status": "ok",
        "feature_names": FEATURE_NAMES,
        "evaluation": MODEL_METRICS,
    }


@app.post("/api/analyze")
async def analyze_url(payload: URLAnalyzeRequest):
    """Tek bir URL adresini analiz edip olasılık ve risk faktörlerini döndürür."""
    t_start = time.perf_counter()
    url_clean = payload.url.strip()
    if not url_clean:
        raise HTTPException(status_code=400, detail="URL adresi boş olamaz.")

    try:
        raw_features, model_features = extract_features_for_model(url_clean)
        ordered_row = {col: model_features.get(col, 0) for col in FEATURE_NAMES}
        X_input = pd.DataFrame([ordered_row], columns=FEATURE_NAMES)

        proba = MODEL.predict_proba(X_input)[0]
        benign_prob = float(proba[0])
        phishing_prob = float(proba[1])
        latency_ms = (time.perf_counter() - t_start) * 1000

        return build_analysis_result(url_clean, raw_features, benign_prob, phishing_prob, latency_ms)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"URL analizi sırasında hata: {str(exc)}")


@app.post("/api/batch-analyze")
@app.post("/api/analyze/batch")
async def batch_analyze_urls(payload: BatchURLAnalyzeRequest):
    """Birden fazla URL adresini toplu olarak analiz eder."""
    t_batch_start = time.perf_counter()
    cleaned_urls = [u.strip() for u in payload.urls if u and u.strip()]

    if not cleaned_urls:
        raise HTTPException(status_code=400, detail="Analiz edilecek geçerli bir URL bulunamadı.")
    if len(cleaned_urls) > MAX_BATCH_URLS:
        raise HTTPException(
            status_code=400,
            detail=f"Tek seferde en fazla {MAX_BATCH_URLS} URL analiz edilebilir (gönderilen: {len(cleaned_urls)}).",
        )

    try:
        feature_list: List[Dict[str, Any]] = []
        ordered_rows: List[Dict[str, Any]] = []
        feature_timings_ms: List[float] = []

        for url_clean in cleaned_urls:
            t_feat = time.perf_counter()
            raw_feats, model_feats = extract_features_for_model(url_clean)
            feature_timings_ms.append((time.perf_counter() - t_feat) * 1000)
            feature_list.append(raw_feats)
            ordered_rows.append({col: model_feats.get(col, 0) for col in FEATURE_NAMES})

        t_pred_start = time.perf_counter()
        X_batch = pd.DataFrame(ordered_rows, columns=FEATURE_NAMES)
        probas = MODEL.predict_proba(X_batch)
        pred_per_url_ms = ((time.perf_counter() - t_pred_start) * 1000) / len(cleaned_urls)

        results: List[Dict[str, Any]] = []
        phishing_count = 0
        for idx, url_clean in enumerate(cleaned_urls):
            benign_prob = float(probas[idx][0])
            phishing_prob = float(probas[idx][1])
            item_latency_ms = feature_timings_ms[idx] + pred_per_url_ms
            item = build_analysis_result(
                url_clean,
                feature_list[idx],
                benign_prob,
                phishing_prob,
                item_latency_ms,
            )
            if item["is_phishing"]:
                phishing_count += 1
            results.append(item)

        total_latency_ms = round((time.perf_counter() - t_batch_start) * 1000, 3)
        avg_latency_per_url_ms = round(total_latency_ms / len(cleaned_urls), 3)

        return {
            "total_urls": len(cleaned_urls),
            "phishing_count": phishing_count,
            "benign_count": len(cleaned_urls) - phishing_count,
            "total_latency_ms": total_latency_ms,
            "avg_latency_per_url_ms": avg_latency_per_url_ms,
            "meets_latency_sla": bool(avg_latency_per_url_ms < SLA_MAX_LATENCY_MS),
            "results": results,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Toplu URL analizi sırasında hata: {str(exc)}")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "127.0.0.1")
    uvicorn.run("api.main:app", host=host, port=port, reload=True)
