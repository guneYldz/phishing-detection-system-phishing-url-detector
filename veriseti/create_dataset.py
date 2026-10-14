import os
import csv
import random

def create_dataset(phishing_csv, benign_csv, output_csv, seed=42):
    print("Veri setleri okunuyor...")
    
    rows = []
    seen_urls = set()
    phishing_count = 0
    benign_count = 0

    # 1. Phishing verilerini oku
    with open(phishing_csv, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if not row or len(row) < 2:
                continue
            url, label = row[0].strip(), row[1].strip()
            if url not in seen_urls:
                seen_urls.add(url)
                rows.append([url, int(label)])
                phishing_count += 1

    print(f"Phishing URL sayısı: {phishing_count:,}")

    # 2. Benign verilerini oku (çakışma kontrolü ile)
    collision_count = 0
    with open(benign_csv, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if not row or len(row) < 2:
                continue
            url, label = row[0].strip(), row[1].strip()
            if url in seen_urls:
                collision_count += 1
                continue
            seen_urls.add(url)
            rows.append([url, int(label)])
            benign_count += 1

    print(f"Benign URL sayısı: {benign_count:,} (Çakışan: {collision_count})")
    print(f"Toplam birleştirilen satır: {len(rows):,}")

    # 3. Rastgele karıştır (Shuffle)
    print(f"Veriler karıştırılıyor (seed={seed})...")
    random.seed(seed)
    random.shuffle(rows)

    # 4. dataset.csv olarak kaydet
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        writer.writerows(rows)

    file_size_mb = os.path.getsize(output_csv) / (1024 * 1024)

    return {
        'output_csv': output_csv,
        'total_rows': len(rows),
        'phishing_count': phishing_count,
        'benign_count': benign_count,
        'file_size_mb': file_size_mb,
        'samples': rows[:10]
    }

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.abspath(__file__))
    phishing_file = os.path.join(base_dir, 'phishing_urls.csv')
    benign_file = os.path.join(base_dir, 'benign_urls.csv')
    output_file = os.path.join(base_dir, 'dataset.csv')

    stats = create_dataset(phishing_file, benign_file, output_file)

    print("\n" + "="*50)
    print("NİHAİ DATASET.CSV BAŞARIYLA OLUŞTURULDU")
    print("="*50)
    print(f"Dosya Yolu      : {stats['output_csv']}")
    print(f"Dosya Boyutu    : {stats['file_size_mb']:.2f} MB")
    print(f"Toplam Satır    : {stats['total_rows']:,}")
    print(f"Phishing (1)    : {stats['phishing_count']:,} (%{stats['phishing_count']/stats['total_rows']*100:.1f})")
    print(f"Benign (0)      : {stats['benign_count']:,} (%{stats['benign_count']/stats['total_rows']*100:.1f})")
    print("\nKarıştırılmış İlk 10 Satır Örneği:")
    for url, label in stats['samples']:
        tag = "[PHISHING - 1]" if label == 1 else "[GÜVENLİ  - 0]"
        print(f"  {tag} {url}")
