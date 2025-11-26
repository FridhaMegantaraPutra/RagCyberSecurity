import requests
import json
from datetime import datetime, timedelta

def ambil_data_cve():
    """
    Fungsi untuk mengambil data CVE dari NVD API dan menyimpan sebagai JSON
    """
    # Hitung tanggal untuk 3 bulan terakhir
    tanggal_akhir = datetime.now()
    tanggal_awal = tanggal_akhir - timedelta(days=60)
    
    # Format tanggal untuk URL
    pub_start_date = tanggal_awal.strftime("%Y-%m-%dT00:00:00.000Z")
    pub_end_date = tanggal_akhir.strftime("%Y-%m-%dT23:59:59.999Z")
    
    # URL API NVD
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={pub_start_date}&pubEndDate={pub_end_date}"
    
    print("Mengambil data CVE dari NVD API...")
    
    try:
        # Request data dari API
        response = requests.get(url)
        response.raise_for_status()
        
        # Parse data JSON
        data_cve = response.json()
        
        # Simpan ke file JSON
        with open('data_cve.json', 'w', encoding='utf-8') as file:
            json.dump(data_cve, file, indent=2, ensure_ascii=False)
        
        # Hitung total CVE yang didapat
        total_cve = data_cve.get('totalResults', 0)
        print(f"Berhasil mengambil {total_cve} records CVE")
        print("Data disimpan dalam file: data_cve.json")
        
        return data_cve
        
    except requests.exceptions.RequestException as e:
        print(f"Error saat mengambil data: {e}")
        return None

def proses_data_cve():
    """
    Fungsi untuk memproses data CVE dan menyimpan dalam format yang lebih bersih
    """
    try:
        # Baca file JSON
        with open('data_cve.json', 'r', encoding='utf-8') as file:
            data_cve = json.load(file)
        
        # Ekstrak hanya informasi penting
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
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                base_score = cvss_data.get('baseScore', 0.0)
                base_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            
            # Format data CVE
            cve_item = {
                'id': cve_info.get('id', ''),
                'description': description_en,
                'published_date': cve_info.get('published', ''),
                'last_modified': cve_info.get('lastModified', ''),
                'status': cve_info.get('vulnStatus', ''),
                'base_score': base_score,
                'severity': base_severity,
                'vector_string': cvss_data.get('vectorString', ''),
                'attack_vector': cvss_data.get('attackVector', ''),
                'attack_complexity': cvss_data.get('attackComplexity', ''),
                'privileges_required': cvss_data.get('privilegesRequired', ''),
                'user_interaction': cvss_data.get('userInteraction', ''),
                'scope': cvss_data.get('scope', ''),
                'confidentiality_impact': cvss_data.get('confidentialityImpact', ''),
                'integrity_impact': cvss_data.get('integrityImpact', ''),
                'availability_impact': cvss_data.get('availabilityImpact', '')
            }
            
            cve_processed.append(cve_item)
        
        # Simpan data yang sudah diproses
        with open('cve_processed.json', 'w', encoding='utf-8') as file:
            json.dump(cve_processed, file, indent=2, ensure_ascii=False)
        
        print(f"Berhasil memproses {len(cve_processed)} records CVE")
        print("Data processed disimpan dalam file: cve_processed.json")
        
        return cve_processed
        
    except Exception as e:
        print(f"Error saat memproses data: {e}")
        return None

if __name__ == "__main__":
    # Jalankan fungsi ambil data
    data_cve = ambil_data_cve()
    
    if data_cve:
        # Proses data
        proses_data_cve()