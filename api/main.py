"""
Phishing URL Detection System - FastAPI REST API Arka Uç Servisi (4. Hafta)
İş Paketi 4 (Aşama 1) Kapsamında:
- 3. haftada eğitilip dondurulan XGBoost modelinin (xgboost_model.joblib) başlangıçta belleğe (RAM) yüklenmesi
- Tekil URL sorgulaması (/api/analyze) için 26 leksikal/sezgisel özelliğin çıkarılması ve <100 ms altında (FOG-4) tahmin üretilmesi
- Açıklanabilir leksikal risk faktörlerinin (FG-4) JSON yanıtı olarak döndürülmesi
- 5. haftada geliştirilecek Web Arayüzü (Frontend) için CORS ve REST uç noktalarının hazırlanması
"""

import os
import sys
import json
import time
from typing import List, Dict, Any

import joblib
import pandas as pd
import xgboost as xgb
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Proje kök dizinini sys.path'e ekle
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from features.extract_features import extract_url_features

app = FastAPI(
    title="Kimlik Avı (Phishing) URL Tespit Sistemi - REST API",
    description=(
        "Fırat Üniversitesi Bilgisayar Mühendisliği Tasarım Dersi Projesi (4. Hafta) — "
        "XGBoost ve Leksikal Özellik Çıkarım Motoru Tabanlı Gerçek Zamanlı Tahmin Arka Ucu"
    ),
    version="0.4.0",
)

# 5. haftada entegre edilecek Web Arayüzü (Frontend) için CORS yapılandırması
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Model ve meta veri yolları
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
XGB_JOBLIB_PATH = os.path.join(MODELS_DIR, "xgboost_model.joblib")
XGB_JSON_PATH = os.path.join(MODELS_DIR, "xgboost_model.json")
FEATURE_NAMES_PATH = os.path.join(MODELS_DIR, "feature_names.joblib")
EVAL_RESULTS_PATH = os.path.join(MODELS_DIR, "model_evaluation_results.json")

MODEL = None
FEATURE_NAMES: List[str] = []
MODEL_METRICS: Dict[str, Any] = {}


def load_artifacts() -> None:
    """Eğitilmiş XGBoost modelini, özellik listesini ve doğrulama metriklerini belleğe yükler."""
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


load_artifacts()


class URLAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=4096, description="Analiz edilecek web adresi (URL)")


def generate_lexical_risk_factors(features: dict, phishing_prob: float) -> List[Dict[str, str]]:
    """
    Çıkarılan 26 leksikal ve sezgisel özelliğe göre açıklanabilir risk faktörleri üretir (FG-4).
    """
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

    if features.get("shannon_entropy", 0.0) >= 4.3:
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


def determine_risk_level(phishing_prob: float) -> str:
    if phishing_prob >= 0.85:
        return "KRİTİK"
    elif phishing_prob >= 0.50:
        return "YÜKSEK"
    elif phishing_prob >= 0.25:
        return "ORTA"
    return "DÜŞÜK (GÜVENLİ)"


@app.get("/")
async def root_status():
    """Servis kök durum bilgisi (5. haftada Web Arayüzü bu katmana bağlanacaktır)."""
    return {
        "service": "Phishing URL Detection REST API",
        "version": "0.4.0 (Week 4 - Backend Core)",
        "docs_url": "/docs",
        "endpoints": ["/api/health", "/api/model-info", "/api/analyze"]
    }


@app.get("/api/health")
async def health_check():
    """Arka uç servisinin ve bellekteki XGBoost modelinin sağlık kontrolünü yapar."""
    return {
        "status": "ok",
        "model_loaded": MODEL is not None,
        "model_type": "XGBoost Classifier",
        "feature_count": len(FEATURE_NAMES),
        "sla_max_latency_ms": 100.0,
    }


@app.get("/api/model-info")
async def get_model_info():
    """3. haftada eğitilen modellerin doğrulama metriklerini ve özellik listesini döndürür."""
    return {
        "status": "ok",
        "feature_names": FEATURE_NAMES,
        "evaluation": MODEL_METRICS,
    }


@app.post("/api/analyze")
async def analyze_url(payload: URLAnalyzeRequest):
    """
    Tekil URL adresini 26 leksikal nitelik ve XGBoost modeliyle gerçek zamanlı analiz eder (FG-4, FOG-4).
    """
    t_start = time.perf_counter()
    url_clean = payload.url.strip()
    if not url_clean:
        raise HTTPException(status_code=400, detail="URL adresi boş olamaz.")

    try:
        features = extract_url_features(url_clean)
        ordered_row = {col: features.get(col, 0) for col in FEATURE_NAMES}
        X_input = pd.DataFrame([ordered_row], columns=FEATURE_NAMES)

        proba = MODEL.predict_proba(X_input)[0]
        benign_prob = float(proba[0])
        phishing_prob = float(proba[1])
        pred_label = int(1 if phishing_prob >= 0.50 else 0)

        latency_ms = round((time.perf_counter() - t_start) * 1000, 3)
        risk_factors = generate_lexical_risk_factors(features, phishing_prob)

        return {
            "url": url_clean,
            "prediction": pred_label,
            "label": "PHISHING" if pred_label == 1 else "BENIGN",
            "is_phishing": bool(pred_label == 1),
            "phishing_probability": round(phishing_prob, 4),
            "benign_probability": round(benign_prob, 4),
            "risk_level": determine_risk_level(phishing_prob),
            "latency_ms": latency_ms,
            "meets_latency_sla": bool(latency_ms < 100.0),
            "risk_factors": risk_factors,
            "lexical_features": features,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"URL analizi sırasında hata: {str(exc)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)

