import json
import pickle
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import re
from datetime import datetime

def chunk_text(text, max_length=512):
    """
    Fungsi untuk melakukan chunking pada teks deskripsi CVE
    """
    # Bersihkan teks
    text = re.sub(r'\s+', ' ', text).strip()
    
    # Jika teks sudah pendek, return langsung
    if len(text) <= max_length:
        return [text]
    
    # Split oleh kalimat untuk chunking yang lebih natural
    sentences = re.split(r'[.!?]+', text)
    chunks = []
    current_chunk = ""
    
    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue
            
        # Jika menambahkan kalimat ini melebihi max_length
        if len(current_chunk) + len(sentence) + 1 > max_length:
            if current_chunk:
                chunks.append(current_chunk.strip())
            current_chunk = sentence
        else:
            if current_chunk:
                current_chunk += ". " + sentence
            else:
                current_chunk = sentence
    
    # Tambahkan chunk terakhir
    if current_chunk:
        chunks.append(current_chunk.strip())
    
    return chunks

def buat_embedding_dan_simpan():
    """
    Fungsi untuk membuat embedding dan menyimpan dalam format pickle
    """
    try:
        # Load data yang sudah diproses (5 tahun)
        with open('cve_processed_5tahun.json', 'r', encoding='utf-8') as file:
            data_cve = json.load(file)
        
        print(f"Memproses {len(data_cve)} records CVE untuk embedding...")
        
        # Load model embedding
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        data_untuk_embedding = []
        metadata_list = []
        
        # Proses setiap CVE
        for i, cve in enumerate(data_cve):
            if i % 1000 == 0:
                print(f"Memproses CVE ke-{i}/{len(data_cve)}...")
            
            # Gabungkan informasi penting untuk embedding
            text_untuk_embedding = f"""
            CVE ID: {cve['id']}
            Description: {cve['description']}
            Severity: {cve['severity']}
            CVSS Score: {cve['base_score']}
            Attack Vector: {cve['attack_vector']}
            Attack Complexity: {cve['attack_complexity']}
            Privileges Required: {cve['privileges_required']}
            User Interaction: {cve['user_interaction']}
            Scope: {cve['scope']}
            Confidentiality Impact: {cve['confidentiality_impact']}
            Integrity Impact: {cve['integrity_impact']}
            Availability Impact: {cve['availability_impact']}
            Weaknesses: {', '.join(cve.get('weaknesses', []))}
            Published Date: {cve['published_date']}
            """.strip()
            
            # Lakukan chunking
            chunks = chunk_text(text_untuk_embedding)
            
            for chunk in chunks:
                data_untuk_embedding.append(chunk)
                metadata_list.append({
                    'cve_id': cve['id'],
                    'chunk_text': chunk,
                    'severity': cve['severity'],
                    'base_score': cve['base_score'],
                    'published_date': cve['published_date'],
                    'year': cve['year'],
                    'vector_string': cve.get('vector_string', ''),
                    'weaknesses': cve.get('weaknesses', []),
                    'full_description': cve['description'][:500]  # Simpan sebagian deskripsi lengkap
                })
        
        print(f"Menghasilkan {len(data_untuk_embedding)} chunks untuk embedding...")
        print("Membuat embeddings, ini mungkin memerlukan waktu beberapa menit...")
        
        # Buat embedding dengan batch processing untuk menghemat memory
        batch_size = 32
        embeddings_list = []
        
        for i in range(0, len(data_untuk_embedding), batch_size):
            batch_texts = data_untuk_embedding[i:i + batch_size]
            batch_embeddings = model.encode(batch_texts, show_progress_bar=False)
            embeddings_list.append(batch_embeddings)
            
            if i % (batch_size * 10) == 0:
                print(f"Progress embedding: {min(i + batch_size, len(data_untuk_embedding))}/{len(data_untuk_embedding)}")
        
        # Gabungkan semua embeddings
        embeddings = np.vstack(embeddings_list)
        
        # Simpan data dalam pickle
        data_untuk_disimpan = {
            'embeddings': embeddings,
            'metadata': metadata_list,
            'chunk_texts': data_untuk_embedding,
            'model_name': 'all-MiniLM-L6-v2',
            'created_date': datetime.now().isoformat(),
            'total_cve': len(data_cve),
            'total_chunks': len(data_untuk_embedding)
        }
        
        with open('cve_embeddings_5tahun.pkl', 'wb') as file:
            pickle.dump(data_untuk_disimpan, file)
        
        print("Embedding berhasil dibuat dan disimpan dalam file: cve_embeddings_5tahun.pkl")
        print(f"Shape embeddings: {embeddings.shape}")
        print(f"Total CVE: {len(data_cve)}")
        print(f"Total chunks: {len(data_untuk_embedding)}")
        
        return data_untuk_disimpan
        
    except FileNotFoundError:
        print("File cve_processed_5tahun.json tidak ditemukan. Jalankan proses_data_cve() terlebih dahulu.")
        return None
    except Exception as e:
        print(f"Error dalam proses embedding: {e}")
        return None

def cari_similaritas_cosine(query, data_embedding, top_k=5):
    """
    Fungsi untuk mencari similarity menggunakan cosine similarity
    """
    try:
        # Load model embedding
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Embed query
        query_embedding = model.encode([query])
        
        # Hitung cosine similarity
        similarities = cosine_similarity(query_embedding, data_embedding['embeddings'])
        
        # Dapatkan index dengan similarity tertinggi
        sorted_indices = np.argsort(similarities[0])[::-1][:top_k]
        
        results = []
        for idx in sorted_indices:
            results.append({
                'metadata': data_embedding['metadata'][idx],
                'chunk_text': data_embedding['chunk_texts'][idx],
                'similarity': similarities[0][idx]
            })
        
        return results
        
    except Exception as e:
        print(f"Error dalam similarity search: {e}")
        return []

def cari_cve_by_teknologi(teknologi, data_embedding, top_k=10):
    """
    Fungsi khusus untuk mencari CVE berdasarkan teknologi
    """
    query_map = {
        'apache': 'Apache Log4j Struts Tomcat HTTP Server',
        'microsoft': 'Microsoft Windows Exchange Server IIS .NET Azure',
        'linux': 'Linux Ubuntu Debian RedHat CentOS Kernel',
        'oracle': 'Oracle Database Java WebLogic MySQL',
        'sql_injection': 'SQL injection SQLi database query',
        'xss': 'cross-site scripting XSS',
        'rce': 'remote code execution RCE arbitrary code execution',
        'critical': 'critical severity high score CVSS'
    }
    
    if teknologi.lower() in query_map:
        query = query_map[teknologi.lower()]
    else:
        query = teknologi
    
    return cari_similaritas_cosine(query, data_embedding, top_k)

def load_embeddings():
    """
    Fungsi untuk load embeddings dari file
    """
    try:
        with open('cve_embeddings_5tahun.pkl', 'rb') as file:
            data_embedding = pickle.load(file)
        print(f"Embeddings berhasil dimuat: {len(data_embedding['metadata'])} chunks")
        return data_embedding
    except FileNotFoundError:
        print("File cve_embeddings_5tahun.pkl tidak ditemukan. Jalankan buat_embedding_dan_simpan() terlebih dahulu.")
        return None

def test_queries():
    """
    Fungsi untuk testing berbagai jenis query
    """
    data_embedding = load_embeddings()
    if not data_embedding:
        return
    
    test_queries = [
        "Apache Log4j critical vulnerabilities",
        "Microsoft Exchange Server security issues",
        "SQL injection in database systems",
        "Linux kernel privilege escalation",
        "remote code execution high severity",
        "cross-site scripting XSS web applications"
    ]
    
    for query in test_queries:
        print(f"\n{'='*60}")
        print(f"QUERY: {query}")
        print(f"{'='*60}")
        
        results = cari_similaritas_cosine(query, data_embedding, top_k=3)
        
        for i, result in enumerate(results, 1):
            print(f"\n--- Result {i} (Similarity: {result['similarity']:.4f}) ---")
            print(f"CVE ID: {result['metadata']['cve_id']}")
            print(f"Severity: {result['metadata']['severity']} (Score: {result['metadata']['base_score']})")
            print(f"Published: {result['metadata']['published_date']}")
            print(f"Description: {result['metadata']['full_description'][:200]}...")

if __name__ == "__main__":
    # Buat dan simpan embedding
    print("Membuat embedding untuk data CVE 5 tahun...")
    data_embedding = buat_embedding_dan_simpan()
    
    if data_embedding:
        # Test berbagai query
        print("\nMelakukan testing queries...")
        test_queries()