import os
import csv
import zipfile
import io
import urllib.request
from collections import Counter

TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip'

def download_and_extract_benign(output_csv, target_count=50000):
    print("Tranco Top 1M listesi indiriliyor...")
    req = urllib.request.Request(TRANCO_URL, headers={'User-Agent': 'Mozilla/5.0'})
    
    with urllib.request.urlopen(req, timeout=60) as resp:
        zip_bytes = resp.read()
    print(f"İndirme tamamlandı! ({len(zip_bytes)/1024/1024:.2f} MB). Veriler ayıklanıyor...")

    benign_urls = []
    tlds = []

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        csv_filename = z.namelist()[0]
        with z.open(csv_filename) as f:
            for idx, line in enumerate(f):
                if len(benign_urls) >= target_count:
                    break
                decoded = line.decode('utf-8', errors='ignore').strip()
                if not decoded or ',' not in decoded:
                    continue
                
                parts = decoded.split(',', 1)
                domain = parts[1].strip()

                # Standart URL formatına dönüştürme: https://domain/
                # Güvenli sitelerin dünya standardı HTTPS'tir.
                url = f"https://{domain}/"
                benign_urls.append(url)

                # TLD analizi
                tld = domain.split('.')[-1].lower() if '.' in domain else 'other'
                tlds.append(tld)

    # CSV olarak kaydet
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        for u in benign_urls:
            writer.writerow([u, 0])

    file_size_kb = os.path.getsize(output_csv) / 1024
    top_tlds = Counter(tlds).most_common(5)

    return {
        'total_extracted': len(benign_urls),
        'file_path': output_csv,
        'file_size_kb': file_size_kb,
        'top_tlds': top_tlds,
        'samples': benign_urls[:5]
    }

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(base_dir, 'benign_urls.csv')
    
    stats = download_and_extract_benign(output_file, target_count=50000)
    
    print("\n" + "="*50)
    print("GÜVENLİ (BENIGN) VERİ AYIKLAMA TAMAMLANDI")
    print("="*50)
    print(f"Kaydedilen dosya    : {stats['file_path']}")
    print(f"Dosya boyutu        : {stats['file_size_kb']:.2f} KB ({stats['file_size_kb']/1024:.2f} MB)")
    print(f"Benzersiz URL sayısı: {stats['total_extracted']:,}")
    print(f"Etiket              : 0 (Benign / Güvenli)")
    print(f"En çok geçen TLD'ler: {stats['top_tlds']}")
    print("\nÖrnek Çıktılar (İlk 5):")
    for s in stats['samples']:
        print(f"  - {s}")
