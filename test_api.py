"""
Phishing URL Tespit Sistemi - API, Web Arayüzü ve Docker Dağıtım Doğrulama Testleri (7. Hafta)
Web arayüzü, tekil analiz, toplu URL tarama, gecikme (<100 ms), hata senaryoları ve Docker yapılandırmalarını test eder.
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

from api.main import app, MAX_BATCH_URLS, API_VERSION

client = TestClient(app)


def measure_get(path: str):
    t0 = time.perf_counter()
    resp = client.get(path)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
    return resp, elapsed_ms


def verify_docker_artifacts() -> dict:
    """Dockerfile, docker-compose.yml ve .dockerignore dosyalarının varlığını ve bütünlüğünü doğrular."""
    t0 = time.perf_counter()
    dockerfile_path = os.path.join(PROJECT_ROOT, "Dockerfile")
    compose_path = os.path.join(PROJECT_ROOT, "docker-compose.yml")
    dockerignore_path = os.path.join(PROJECT_ROOT, ".dockerignore")

    assert os.path.exists(dockerfile_path), "Dockerfile bulunamadı!"
    assert os.path.exists(compose_path), "docker-compose.yml bulunamadı!"
    assert os.path.exists(dockerignore_path), ".dockerignore bulunamadı!"

    with open(dockerfile_path, "r", encoding="utf-8") as f:
        df_content = f.read()
    assert "FROM python:3.11-slim" in df_content
    assert "EXPOSE 8000" in df_content
    assert "HEALTHCHECK" in df_content
    assert "api.main:app" in df_content

    with open(compose_path, "r", encoding="utf-8") as f:
        dc_content = f.read()
    assert "phishguard-ai" in dc_content
    assert "8000:8000" in dc_content
    assert "healthcheck:" in dc_content

    with open(dockerignore_path, "r", encoding="utf-8") as f:
        di_content = f.read()
    assert "veriseti/" in di_content

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)
    return {
        "dockerfile_valid": True,
        "docker_compose_valid": True,
        "dockerignore_valid": True,
        "check_latency_ms": elapsed_ms,
    }


def run_api_tests():
    print("=" * 70)
    print(f"PHISHGUARD AI (v{API_VERSION}) - API, ARAYÜZ VE DOCKER HAZIRLIK TESTLERİ")
    print("=" * 70)

    endpoint_latencies = {}

    # 1. Web arayüzü ve statik dosya uç noktaları
    r_root, lat_root = measure_get("/")
    assert r_root.status_code == 200
    assert "PhishGuard AI" in r_root.text and "Toplu URL Tarama" in r_root.text
    assert 'href="style.css"' in r_root.text and 'src="app.js"' in r_root.text
    assert lat_root < 100.0

    r_ui, lat_ui = measure_get("/ui")
    assert r_ui.status_code == 200
    assert "PhishGuard AI" in r_ui.text
    assert lat_ui < 100.0

    r_css, lat_css = measure_get("/style.css")
    assert r_css.status_code == 200 and ".topbar" in r_css.text

    r_js, lat_js = measure_get("/app.js")
    assert r_js.status_code == 200 and "analyzeBatchUrls" in r_js.text

    assert client.get("/ui/style.css").status_code == 200
    assert client.get("/ui/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200

    endpoint_latencies["ui_avg_ms"] = round((lat_root + lat_ui) / 2, 3)
    endpoint_latencies["static_avg_ms"] = round((lat_css + lat_js) / 2, 3)
    print(
        f"[OK] GET /, /ui, /static/* -> Arayüz ve statik dosyalar yüklendi "
        f"(HTML Ort: {endpoint_latencies['ui_avg_ms']} ms, CSS/JS Ort: {endpoint_latencies['static_avg_ms']} ms)"
    )

    # 2. Servis, konteyner sağlık ve model bilgisi kontrolleri
    r_api, lat_api = measure_get("/api")
    assert r_api.status_code == 200
    api_data = r_api.json()
    assert "/api/batch-analyze" in api_data.get("endpoints", [])
    assert api_data.get("container_ready") is True
    endpoint_latencies["api_root_ms"] = lat_api
    print(f"[OK] GET /api -> Sürüm: {api_data['version']} | Container Ready: {api_data['container_ready']} ({lat_api} ms)")

    r_health, lat_health = measure_get("/api/health")
    assert r_health.status_code == 200
    h_data = r_health.json()
    assert h_data["status"] == "ok" and h_data["model_loaded"] is True
    assert h_data.get("container_ready") is True and "uptime_seconds" in h_data
    endpoint_latencies["health_ms"] = lat_health
    print(
        f"[OK] GET /api/health -> Model hazır ({h_data['feature_count']} özellik, "
        f"Ortam: {h_data['environment']}, {lat_health} ms)"
    )

    r_info, lat_info = measure_get("/api/model-info")
    assert r_info.status_code == 200
    info_data = r_info.json()
    assert info_data["status"] == "ok" and len(info_data["feature_names"]) == 26
    endpoint_latencies["model_info_ms"] = lat_info
    print(f"[OK] GET /api/model-info -> Model metrikleri alındı ({lat_info} ms)")

    # 3. Tekil URL analizi testleri
    samples = [
        ("https://www.google.com/", 0),
        ("https://www.firat.edu.tr/", 0),
        ("https://www.youtube.com/watch?v=Z7_fQqhQfto", 0),
        ("https://github.com/torvalds/linux", 0),
        ("http://192.168.1.105/banking/login.php?session=98123", 1),
        ("http://paypal-secure-login.account-update.xyz/verify?user=admin", 1),
        ("https://apple-id-support-verify.serveo.net/signin", 1),
    ]

    single_latencies = []
    single_correct = 0

    print("\n--- Tekil URL Analizi (/api/analyze) ---")
    for url, expected in samples:
        resp = client.post("/api/analyze", json={"url": url})
        assert resp.status_code == 200
        data = resp.json()
        assert data["latency_ms"] < 100.0
        assert data["meets_latency_sla"] is True
        assert isinstance(data["risk_factors"], list) and len(data["risk_factors"]) >= 1
        single_latencies.append(data["latency_ms"])
        if data["prediction"] == expected:
            single_correct += 1
        print(
            f"  -> {url[:48]:48s} | Tahmin: {data['label']:8s} | "
            f"Olasılık: {data['phishing_probability']:.4f} | Süre: {data['latency_ms']:.3f} ms"
        )

    avg_single_lat = round(sum(single_latencies) / len(single_latencies), 3)
    max_single_lat = round(max(single_latencies), 3)
    endpoint_latencies["analyze_avg_ms"] = avg_single_lat
    endpoint_latencies["analyze_max_ms"] = max_single_lat

    # 4. Toplu URL tarama testleri
    print("\n--- Toplu URL Tarama (/api/batch-analyze) ---")
    batch_urls = [u for u, _ in samples]
    r_batch = client.post("/api/batch-analyze", json={"urls": batch_urls})
    assert r_batch.status_code == 200
    b_data = r_batch.json()

    assert b_data["total_urls"] == len(batch_urls)
    assert b_data["phishing_count"] + b_data["benign_count"] == b_data["total_urls"]
    assert len(b_data["results"]) == len(batch_urls)
    assert b_data["avg_latency_per_url_ms"] < 100.0
    assert b_data["meets_latency_sla"] is True

    batch_correct = sum(
        1 for idx, item in enumerate(b_data["results"]) if item["prediction"] == samples[idx][1]
    )
    endpoint_latencies["batch_total_ms"] = b_data["total_latency_ms"]
    endpoint_latencies["batch_avg_per_url_ms"] = b_data["avg_latency_per_url_ms"]
    print(
        f"[OK] POST /api/batch-analyze -> {b_data['total_urls']} URL | "
        f"Phishing: {b_data['phishing_count']}, Benign: {b_data['benign_count']} | "
        f"Toplam: {b_data['total_latency_ms']} ms | Ort/URL: {b_data['avg_latency_per_url_ms']} ms"
    )

    # 5. Geçersiz girdi ve sınır durumu testleri
    print("\n--- Hata ve Sınır Durumu Testleri ---")
    t_err0 = time.perf_counter()

    r_empty = client.post("/api/analyze", json={"url": ""})
    assert r_empty.status_code in (400, 422)

    r_spaces = client.post("/api/analyze", json={"url": "   "})
    assert r_spaces.status_code == 400

    r_empty_batch = client.post("/api/batch-analyze", json={"urls": []})
    assert r_empty_batch.status_code in (400, 422)

    r_blank_batch = client.post("/api/batch-analyze", json={"urls": ["", "   "]})
    assert r_blank_batch.status_code == 400

    over_limit_urls = [f"https://example{i}.com" for i in range(MAX_BATCH_URLS + 1)]
    r_over_limit = client.post("/api/batch-analyze", json={"urls": over_limit_urls})
    assert r_over_limit.status_code == 400

    r_noscheme = client.post("/api/analyze", json={"url": "firat.edu.tr"})
    assert r_noscheme.status_code == 200
    assert r_noscheme.json()["latency_ms"] < 100.0

    err_tests_avg_ms = round(((time.perf_counter() - t_err0) * 1000) / 6, 3)
    endpoint_latencies["error_tests_avg_ms"] = err_tests_avg_ms
    print(f"[OK] Hata ve sınır durumu testleri (6 senaryo) geçildi (Ort: {err_tests_avg_ms} ms/test)")

    # 6. Docker konteynerizasyon ve dağıtım hazırlık doğrulaması (7. Hafta)
    print("\n--- Docker Konteynerizasyon ve Dağıtım Hazırlık Doğrulaması ---")
    docker_check = verify_docker_artifacts()
    endpoint_latencies["docker_config_check_ms"] = docker_check["check_latency_ms"]
    print(
        f"[OK] Dockerfile, docker-compose.yml ve .dockerignore doğrulandı "
        f"({docker_check['check_latency_ms']} ms)"
    )

    summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "week": 7,
        "version": API_VERSION,
        "scope": "Docker konteynerizasyon, web arayüzü, tekil/toplu tarama ve hata toleransı testleri",
        "sample_test_count": len(samples),
        "single_sample_accuracy": round(single_correct / len(samples), 4),
        "batch_sample_accuracy": round(batch_correct / len(samples), 4),
        "avg_inference_latency_ms": avg_single_lat,
        "max_inference_latency_ms": max_single_lat,
        "batch_total_latency_ms": b_data["total_latency_ms"],
        "batch_avg_latency_per_url_ms": b_data["avg_latency_per_url_ms"],
        "endpoint_latencies_ms": endpoint_latencies,
        "error_cases_passed": 6,
        "docker_readiness": docker_check,
        "sla_100ms_passed": True,
    }

    out_path = os.path.join(PROJECT_ROOT, "models", "api_benchmark_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("=" * 70)
    print(
        f"TÜM TESTLER GEÇİLDİ | Tekil Ort: {avg_single_lat} ms | "
        f"Toplu Ort/URL: {b_data['avg_latency_per_url_ms']} ms | Docker Hazır: Evet"
    )
    print("=" * 70)


if __name__ == "__main__":
    run_api_tests()
