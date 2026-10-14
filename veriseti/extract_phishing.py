import os
import subprocess
import csv
from urllib.parse import urlparse
from collections import Counter

def extract_phishing_urls(repo_dir, output_csv, target_count=50000, max_commits=500):
    print(f"Git geçmişi taranıyor: {repo_dir}")
    print(f"Hedef: {target_count:,} benzersiz phishing URL'si (Maks. {max_commits} commit)")

    cmd = ['git', '-C', repo_dir, 'log', '-p', f'-n', str(max_commits), '--', 'feed.txt']
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='ignore')

    unique_urls = set()
    ordered_urls = []
    raw_url_count = 0
    commits_seen = 0

    for line in process.stdout:
        if line.startswith('commit '):
            commits_seen += 1
            if commits_seen % 50 == 0:
                print(f"--> {commits_seen} commit tarandı... ({len(unique_urls):,} benzersiz URL bulundu)")
        
        if line.startswith('+http://') or line.startswith('+https://'):
            raw_url_count += 1
            url = line[1:].strip()
            
            # Basit doğrulama
            if url and url not in unique_urls:
                unique_urls.add(url)
                ordered_urls.append(url)
                if len(unique_urls) >= target_count:
                    print(f"Hedeflenen {target_count:,} adede ulaşıldı!")
                    break

    process.kill()

    # CSV olarak kaydet
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        for u in ordered_urls:
            writer.writerow([u, 1])

    file_size_kb = os.path.getsize(output_csv) / 1024
    
    # İstatistikler
    http_count = sum(1 for u in ordered_urls if u.startswith('http://'))
    https_count = sum(1 for u in ordered_urls if u.startswith('https://'))
    
    tlds = []
    for u in ordered_urls:
        try:
            netloc = urlparse(u).netloc
            tld = netloc.split('.')[-1].split(':')[0].lower() if '.' in netloc else 'other'
            tlds.append(tld)
        except Exception:
            pass
    top_tlds = Counter(tlds).most_common(5)

    return {
        'total_extracted': len(ordered_urls),
        'raw_count': raw_url_count,
        'commits_scanned': commits_seen,
        'file_path': output_csv,
        'file_size_kb': file_size_kb,
        'http_count': http_count,
        'https_count': https_count,
        'top_tlds': top_tlds,
        'samples': ordered_urls[:5]
    }

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.join(base_dir, 'public_feed')
    output_file = os.path.join(base_dir, 'phishing_urls.csv')
    
    stats = extract_phishing_urls(repo_dir, output_file, target_count=50000, max_commits=500)
    
    print("\n" + "="*50)
    print("AYIKLAMA TAMAMLANDI - ÖZET RAPOR")
    print("="*50)
    print(f"Kaydedilen dosya    : {stats['file_path']}")
    print(f"Dosya boyutu        : {stats['file_size_kb']:.2f} KB ({stats['file_size_kb']/1024:.2f} MB)")
    print(f"Taranan commit      : {stats['commits_scanned']}")
    print(f"Toplam ham satır    : {stats['raw_count']:,}")
    print(f"Benzersiz URL sayısı: {stats['total_extracted']:,}")
    print(f"Protokol dağılımı   : HTTPS: {stats['https_count']:,} (%{stats['https_count']/stats['total_extracted']*100:.1f}), HTTP: {stats['http_count']:,} (%{stats['http_count']/stats['total_extracted']*100:.1f})")
    print(f"En çok geçen TLD'ler: {stats['top_tlds']}")
    print("\nÖrnek Çıktılar (İlk 5):")
    for s in stats['samples']:
        print(f"  - {s}")
