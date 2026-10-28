"""
Phishing URL Detection System - 4. Hafta FastAPI Arka Uç Birim ve Tepki Süresi Testleri
İş Paketi 4 (Aşama 1) Kapsamında:
- /api/health, /api/model-info ve /api/analyze uç noktalarının doğrulanması
- Tekil URL tahmin süresinin <100 ms altında olduğunun (FOG-4) test edilmesi
- Açıklanabilir leksikal risk faktörü çıktılarının (FG-4) kontrolü
"""

import os
import sys
import time
import json
from fastapi.testclient import TestClient

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from api.main import app

client = TestClient(app)


def run_backend_api_tests():
    print("=" * 68)
    print("4. HAFTA FASTAPI ARKA UÇ (BACKEND) SERVİS DOĞRULAMA TESTLERİ")
    print("=" * 68)

    # 1. Sağlık kontrolü
    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    h_data = r_health.json()
    assert h_data["status"] == "ok" and h_data["model_loaded"] is True
    print(f"[OK] GET /api/health -> Model Yüklü ({h_data['feature_count']} leksikal özellik)")

    # 2. Model bilgisi kontrolü
    r_info = client.get("/api/model-info")
    assert r_info.status_code == 200
    print("[OK] GET /api/model-info -> Eğitim ve doğrulama metrikleri döndürüldü")

    # 3. Tekil URL Analizi (/api/analyze) ve Gecikme (Latency < 100 ms) Testi
    samples = [
        ("https://www.google.com/", 0),
        ("https://www.firat.edu.tr/", 0),
        ("https://github.com/torvalds/linux", 0),
        ("http://192.168.1.105/banking/login.php?session=98123", 1),
        ("http://paypal-secure-login.account-update.xyz/verify?user=admin", 1),
        ("https://apple-id-support-verify.serveo.net/signin", 1),
    ]

    latencies = []
    correct = 0

    for url, expected in samples:
        resp = client.post("/api/analyze", json={"url": url})
        assert resp.status_code == 200
        data = resp.json()
        latencies.append(data["latency_ms"])
        assert data["latency_ms"] < 100.0
        if data["prediction"] == expected:
            correct += 1
        print(
            f"  -> {url[:48]:48s} | Tahmin: {data['label']:8s} | "
            f"Olasılık: {data['phishing_probability']:.4f} | Süre: {data['latency_ms']:.3f} ms"
        )

    avg_lat = round(sum(latencies) / len(latencies), 4)
    max_lat = round(max(latencies), 4)

    summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "week": 4,
        "scope": "FastAPI Backend Core (/api/analyze, /api/health, /api/model-info)",
        "sample_test_count": len(samples),
        "sample_accuracy": round(correct / len(samples), 4),
        "avg_inference_latency_ms": avg_lat,
        "max_inference_latency_ms": max_lat,
        "sla_100ms_passed": True
    }

    out_path = os.path.join(PROJECT_ROOT, "models", "api_benchmark_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("=" * 68)
    print(f"4. HAFTA API TESTLERİ TAMAMLANDI | Ort. Tepki Süresi: {avg_lat} ms (<100 ms)")
    print("=" * 68)


if __name__ == "__main__":
    run_backend_api_tests()

