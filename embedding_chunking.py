import json
import pickle
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import euclidean_distances
import re

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
        # Load data yang sudah diproses
        with open('cve_processed.json', 'r', encoding='utf-8') as file:
            data_cve = json.load(file)
        
        print(f"Memproses {len(data_cve)} records CVE untuk embedding...")
        
        # Load model embedding
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        data_untuk_embedding = []
        metadata_list = []
        
        # Proses setiap CVE
        for cve in data_cve:
            # Gabungkan informasi penting untuk embedding
            text_untuk_embedding = f"""
            CVE ID: {cve['id']}
            Description: {cve['description']}
            Severity: {cve['severity']}
            CVSS Score: {cve['base_score']}
            Attack Vector: {cve['attack_vector']}
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
                    'published_date': cve['published_date']
                })
        
        print(f"Menghasilkan {len(data_untuk_embedding)} chunks untuk embedding...")
        
        # Buat embedding
        embeddings = model.encode(data_untuk_embedding)
        
        # Simpan data dalam pickle
        data_untuk_disimpan = {
            'embeddings': embeddings,
            'metadata': metadata_list,
            'chunk_texts': data_untuk_embedding
        }
        
        with open('cve_embeddings.pkl', 'wb') as file:
            pickle.dump(data_untuk_disimpan, file)
        
        print("Embedding berhasil dibuat dan disimpan dalam file: cve_embeddings.pkl")
        print(f"Shape embeddings: {embeddings.shape}")
        
        return data_untuk_disimpan
        
    except Exception as e:
        print(f"Error dalam proses embedding: {e}")
        return None

def cari_similaritas_euclidean(query, data_embedding, top_k=5):
    """
    Fungsi untuk mencari similarity menggunakan Euclidean distance
    """
    try:
        # Load model embedding
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Embed query
        query_embedding = model.encode([query])
        
        # Hitung Euclidean distance
        distances = euclidean_distances(query_embedding, data_embedding['embeddings'])
        
        # Dapatkan index dengan distance terkecil (paling similar)
        sorted_indices = np.argsort(distances[0])[:top_k]
        
        results = []
        for idx in sorted_indices:
            results.append({
                'metadata': data_embedding['metadata'][idx],
                'chunk_text': data_embedding['chunk_texts'][idx],
                'distance': distances[0][idx]
            })
        
        return results
        
    except Exception as e:
        print(f"Error dalam similarity search: {e}")
        return []

if __name__ == "__main__":
    # Buat dan simpan embedding
    data_embedding = buat_embedding_dan_simpan()
    
    if data_embedding:
        # Test similarity search
        test_query = "cross site scripting vulnerability"
        results = cari_similaritas_euclidean(test_query, data_embedding)
        
        print(f"\nHasil pencarian untuk: '{test_query}'")
        for i, result in enumerate(results, 1):
            print(f"\n--- Result {i} (Distance: {result['distance']:.4f}) ---")
            print(f"CVE ID: {result['metadata']['cve_id']}")
            print(f"Severity: {result['metadata']['severity']}")
            print(f"Text: {result['chunk_text'][:200]}...")