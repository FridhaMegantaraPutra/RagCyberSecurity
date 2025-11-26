import requests
import json
from datetime import datetime, timedelta
import time
import math

def ambil_data_cve():
    """
    Fungsi untuk mengambil data CVE dari NVD API dengan memperhatikan batasan 120 hari
    """
    print("Program Pengambilan Data CVE")
    print("Catatan: NVD API membatasi rentang waktu maksimal 120 hari per request")
    
    # Hitung tanggal untuk 5 tahun terakhir, tapi kita akan ambil per 120 hari
    tanggal_akhir = datetime.now()
    tanggal_awal = tanggal_akhir - timedelta(days=5*365)
    
    print(f"Rentang waktu target: {tanggal_awal.strftime('%Y-%m-%d')} hingga {tanggal_akhir.strftime('%Y-%m-%d')}")
    print("Mengambil data secara bertahap per 120 hari...")
    
    all_vulnerabilities = []
    current_start = tanggal_awal
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json'
    }
    
    try:
        while current_start < tanggal_akhir:
            # Hitung end date untuk batch ini (maks 120 hari)
            batch_end = min(current_start + timedelta(days=119), tanggal_akhir)
            
            # Format tanggal untuk URL
            pub_start_date = current_start.strftime("%Y-%m-%dT00:00:00.000Z")
            pub_end_date = batch_end.strftime("%Y-%m-%dT23:59:59.999Z")
            
            print(f"Batch: {current_start.strftime('%Y-%m-%d')} hingga {batch_end.strftime('%Y-%m-%d')}")
            
            # Ambil data untuk batch ini
            batch_data = ambil_data_batch(pub_start_date, pub_end_date, headers)
            if batch_data:
                all_vulnerabilities.extend(batch_data)
                print(f"Berhasil: {len(batch_data)} CVE")
            else:
                print("Tidak ada data untuk batch ini")
            
            # Update start date untuk batch berikutnya
            current_start = batch_end + timedelta(days=1)
            
            # Delay untuk rate limiting
            if current_start < tanggal_akhir:
                print("Menunggu 6 detik untuk rate limiting...")
                time.sleep(6)
        
        if not all_vulnerabilities:
            print("Tidak ada data yang berhasil diambil")
            return None
        
        # Format data lengkap
        data_lengkap = {
            'totalResults': len(all_vulnerabilities),
            'vulnerabilities': all_vulnerabilities,
            'timeframe': {
                'startDate': tanggal_awal.strftime("%Y-%m-%dT00:00:00.000Z"),
                'endDate': tanggal_akhir.strftime("%Y-%m-%dT23:59:59.999Z"),
                'duration_days': 5*365
            },
            'retrievalDate': datetime.now().isoformat(),
            'note': 'Data diambil per batch 120 hari sesuai batasan NVD API'
        }
        
        # Simpan ke file JSON
        filename = 'data_cve_5tahun.json'
        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(data_lengkap, file, indent=2, ensure_ascii=False)
        
        print(f"SUKSES! Total {len(all_vulnerabilities)} records CVE berhasil diambil")
        print(f"Data disimpan dalam file: {filename}")
        
        return data_lengkap
        
    except Exception as e:
        print(f"Error dalam proses pengambilan data: {e}")
        return None

def ambil_data_batch(start_date, end_date, headers):
    """
    Mengambil data CVE untuk satu batch (maks 120 hari)
    """
    batch_vulnerabilities = []
    start_index = 0
    results_per_page = 2000
    
    try:
        while True:
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'pubStartDate': start_date,
                'pubEndDate': end_date,
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            
            response = requests.get(base_url, params=params, headers=headers, timeout=60)
            
            if response.status_code != 200:
                print(f"HTTP Error {response.status_code} untuk batch")
                break
            
            data_cve = response.json()
            vulnerabilities = data_cve.get('vulnerabilities', [])
            batch_vulnerabilities.extend(vulnerabilities)
            
            total_results = data_cve.get('totalResults', 0)
            print(f"   Halaman {start_index//results_per_page + 1}: {len(vulnerabilities)} CVE (total: {len(batch_vulnerabilities)}/{total_results})")
            
            if len(vulnerabilities) < results_per_page:
                break
                
            start_index += results_per_page
            time.sleep(2)
            
    except requests.exceptions.RequestException as e:
        print(f"Request error untuk batch: {e}")
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
    
    return batch_vulnerabilities

def proses_data_cve():
    """
    Fungsi untuk memproses data CVE dan menyimpan dalam format yang lebih bersih
    """
    try:
        with open('data_cve_5tahun.json', 'r', encoding='utf-8') as file:
            data_cve = json.load(file)
        
        print(f"Memproses {len(data_cve.get('vulnerabilities', []))} records CVE...")
        
        cve_processed = []
        
        for item in data_cve.get('vulnerabilities', []):
            cve_info = item.get('cve', {})
            
            # Ambil deskripsi dalam bahasa Inggris
            descriptions = cve_info.get('descriptions', [])
            description_en = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description_en = desc.get('value', '')
                    break
            
            # Ambil metrics CVSS
            metrics = cve_info.get('metrics', {})
            cvss_data = {}
            base_score = 0.0
            base_severity = "UNKNOWN"
            cvss_version = "N/A"
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
                base_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                cvss_version = "3.1"
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
                base_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                cvss_version = "3.0"
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
                if base_score >= 7.0:
                    base_severity = "HIGH"
                elif base_score >= 4.0:
                    base_severity = "MEDIUM"
                else:
                    base_severity = "LOW"
                cvss_version = "2.0"
            
            # Ambil informasi CWE
            weaknesses = cve_info.get('weaknesses', [])
            cwe_info = []
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_info.append(desc.get('value', ''))
            
            # Ambil referensi
            references = cve_info.get('references', [])
            ref_urls = [ref.get('url', '') for ref in references]
            
            # Format tanggal
            published = cve_info.get('published', '')
            try:
                if 'T' in published:
                    published_date = datetime.fromisoformat(published.replace('Z', '+00:00')).strftime('%Y-%m-%d')
                else:
                    published_date = published
            except:
                published_date = published.split('T')[0] if 'T' in published else published
            
            # Format data CVE yang lebih lengkap untuk RAG
            cve_item = {
                'id': cve_info.get('id', ''),
                'description': description_en,
                'published_date': published_date,
                'year': published_date[:4] if published_date and len(published_date) >= 4 else 'Unknown',
                'last_modified': cve_info.get('lastModified', ''),
                'status': cve_info.get('vulnStatus', ''),
                'base_score': base_score,
                'severity': base_severity,
                'cvss_version': cvss_version,
                'vector_string': cvss_data.get('vectorString', ''),
                'attack_vector': cvss_data.get('attackVector', ''),
                'attack_complexity': cvss_data.get('attackComplexity', ''),
                'privileges_required': cvss_data.get('privilegesRequired', ''),
                'user_interaction': cvss_data.get('userInteraction', ''),
                'scope': cvss_data.get('scope', ''),
                'confidentiality_impact': cvss_data.get('confidentialityImpact', ''),
                'integrity_impact': cvss_data.get('integrityImpact', ''),
                'availability_impact': cvss_data.get('availabilityImpact', ''),
                'weaknesses': cwe_info,
                'references': ref_urls,
                'search_text': f"{cve_info.get('id', '')} {description_en} {' '.join(cwe_info)} {base_severity}"
            }
            
            cve_processed.append(cve_item)
        
        # Urutkan berdasarkan tanggal publish (terbaru pertama)
        cve_processed.sort(key=lambda x: x['published_date'], reverse=True)
        
        # Simpan data yang sudah diproses
        with open('cve_processed_5tahun.json', 'w', encoding='utf-8') as file:
            json.dump(cve_processed, file, indent=2, ensure_ascii=False)
        
        # Buat summary statistik
        buat_summary_statistik(cve_processed)
        
        print(f"Berhasil memproses {len(cve_processed)} records CVE")
        print("Data processed disimpan dalam file: cve_processed_5tahun.json")
        
        return cve_processed
        
    except FileNotFoundError:
        print("File data_cve_5tahun.json tidak ditemukan. Jalankan ambil_data_cve() terlebih dahulu.")
        return None
    except Exception as e:
        print(f"Error saat memproses data: {e}")
        return None

def buat_summary_statistik(cve_data):
    """
    Fungsi untuk membuat summary statistik dari data CVE
    """
    if not cve_data:
        print("Tidak ada data untuk dianalisis")
        return
    
    severity_count = {}
    yearly_count = {}
    cvss_version_count = {}
    
    for cve in cve_data:
        severity = cve.get('severity', 'UNKNOWN')
        severity_count[severity] = severity_count.get(severity, 0) + 1
        
        year = cve.get('year', 'Unknown')
        yearly_count[year] = yearly_count.get(year, 0) + 1
        
        cvss_ver = cve.get('cvss_version', 'N/A')
        cvss_version_count[cvss_ver] = cvss_version_count.get(cvss_ver, 0) + 1
    
    summary = {
        'total_cve': len(cve_data),
        'timeframe': '5 tahun terakhir',
        'severity_distribution': severity_count,
        'yearly_distribution': dict(sorted(yearly_count.items())),
        'cvss_version_distribution': cvss_version_count,
        'average_score': sum(cve.get('base_score', 0) for cve in cve_data) / len(cve_data)
    }
    
    with open('cve_summary_5tahun.json', 'w', encoding='utf-8') as file:
        json.dump(summary, file, indent=2, ensure_ascii=False)
    
    print("\n=== SUMMARY STATISTIK CVE 5 TAHUN ===")
    print(f"Total CVE: {summary['total_cve']:,}")
    print(f"Rata-rata CVSS Score: {summary['average_score']:.2f}")
    print("\nDistribusi Severity:")
    for severity, count in sorted(severity_count.items(), key=lambda x: x[1], reverse=True):
        percentage = (count/summary['total_cve']*100) if summary['total_cve'] > 0 else 0
        print(f"   {severity}: {count:,} ({percentage:.1f}%)")
    
    print("\nDistribusi per Tahun:")
    for year, count in sorted(yearly_count.items()):
        print(f"   {year}: {count:,}")
    
    print("\nDistribusi CVSS Version:")
    for version, count in sorted(cvss_version_count.items(), key=lambda x: x[1], reverse=True):
        print(f"   {version}: {count:,}")
    
    print(f"\nSummary disimpan dalam file: cve_summary_5tahun.json")

def buat_index_pencarian():
    """
    Membuat index pencarian untuk memudahkan query
    """
    try:
        with open('cve_processed_5tahun.json', 'r', encoding='utf-8') as file:
            cve_data = json.load(file)
        
        # Buat index berdasarkan teknologi
        index_teknologi = {
            'apache': [],
            'microsoft': [],
            'linux': [],
            'oracle': [],
            'ibm': [],
            'google': [],
            'apple': [],
            'adobe': [],
            'cisco': [],
            'vmware': []
        }
        
        # Buat index berdasarkan jenis vulnerability
        index_jenis = {
            'sql_injection': [],
            'xss': [],
            'rce': [],
            'privilege_escalation': [],
            'dos': [],
            'memory_corruption': [],
            'buffer_overflow': []
        }
        
        for cve in cve_data:
            desc = cve.get('description', '').lower()
            cve_id = cve.get('id', '')
            search_text = cve.get('search_text', '').lower()
            
            # Index berdasarkan teknologi
            if any(tech in search_text for tech in ['apache', 'log4j', 'struts', 'tomcat', 'http server']):
                index_teknologi['apache'].append(cve_id)
            if any(tech in search_text for tech in ['microsoft', 'windows', 'exchange', 'iis', '.net', 'azure']):
                index_teknologi['microsoft'].append(cve_id)
            if any(tech in search_text for tech in ['linux', 'ubuntu', 'debian', 'redhat', 'centos', 'kernel']):
                index_teknologi['linux'].append(cve_id)
            if any(tech in search_text for tech in ['oracle', 'database', 'java', 'weblogic']):
                index_teknologi['oracle'].append(cve_id)
            
            # Index berdasarkan jenis vulnerability
            if any(vuln in search_text for vuln in ['sql injection', 'sqli']):
                index_jenis['sql_injection'].append(cve_id)
            if any(vuln in search_text for vuln in ['cross-site scripting', 'xss']):
                index_jenis['xss'].append(cve_id)
            if any(vuln in search_text for vuln in ['remote code execution', 'rce', 'arbitrary code execution']):
                index_jenis['rce'].append(cve_id)
            if any(vuln in search_text for vuln in ['privilege escalation', 'privileged']):
                index_jenis['privilege_escalation'].append(cve_id)
            if any(vuln in search_text for vuln in ['denial of service', 'dos', 'ddos']):
                index_jenis['dos'].append(cve_id)
        
        index_data = {
            'teknologi': index_teknologi,
            'jenis_vulnerability': index_jenis,
            'total_cve': len(cve_data),
            'created_date': datetime.now().isoformat()
        }
        
        with open('cve_search_index.json', 'w', encoding='utf-8') as file:
            json.dump(index_data, file, indent=2, ensure_ascii=False)
        
        print("Index pencarian berhasil dibuat: cve_search_index.json")
        
        return index_data
        
    except Exception as e:
        print(f"Error membuat index pencarian: {e}")
        return None

if __name__ == "__main__":
    # Jalankan fungsi ambil data
    data_cve = ambil_data_cve()
    
    if data_cve:
        # Proses data
        data_processed = proses_data_cve()
        
        # Buat index pencarian
        if data_processed:
            buat_index_pencarian()