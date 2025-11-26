import streamlit as st
import pickle
import os
from dotenv import load_dotenv
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import euclidean_distances
from groq import Groq

# Load environment variables
load_dotenv()

def cari_similaritas_euclidean(query, data_embedding, top_k=3):
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
        st.error(f"Error dalam similarity search: {e}")
        return []

class CVEChatbot:
    def __init__(self):
        """
        Inisialisasi Chatbot System dengan Groq API
        """
        self.api_key = os.getenv('GROQ_API_KEY')
        if not self.api_key:
            st.error("GROQ_API_KEY tidak ditemukan di file .env")
            st.stop()
        
        # Initialize Groq client
        self.client = Groq(api_key=self.api_key)
        
        # Load embeddings data
        try:
            with open('cve_embeddings.pkl', 'rb') as file:
                self.data_embedding = pickle.load(file)
        except FileNotFoundError:
            st.error("File embeddings tidak ditemukan. Jalankan embedding_chunking.py terlebih dahulu.")
            st.stop()
        except Exception as e:
            st.error(f"Error loading embeddings: {e}")
            st.stop()
    
    def cari_context_relevan(self, query, top_k=3):
        """
        Mencari context yang relevan berdasarkan query
        """
        try:
            results = cari_similaritas_euclidean(query, self.data_embedding, top_k=top_k)
            return results
        except Exception as e:
            st.error(f"Error dalam mencari context: {e}")
            return []
    
    def format_context_untuk_prompt(self, results):
        """
        Format context untuk dimasukkan ke prompt
        """
        if not results:
            return "Tidak ada informasi CVE yang relevan ditemukan."
        
        context_text = "INFORMASI CVE YANG RELEVAN:\n\n"
        for i, result in enumerate(results, 1):
            context_text += f"• {result['metadata']['cve_id']} - {result['metadata']['severity']} (Score: {result['metadata']['base_score']})\n"
            context_text += f"  {result['chunk_text']}\n"
            context_text += f"  Published: {result['metadata']['published_date'][:10]}\n\n"
        
        return context_text

def init_session_state():
    """
    Initialize session state untuk chatbot
    """
    if "messages" not in st.session_state:
        st.session_state.messages = []
    
    if "chatbot" not in st.session_state:
        with st.spinner("Memuat sistem cybersecurity..."):
            st.session_state.chatbot = CVEChatbot()

# Konfigurasi halaman Streamlit
st.set_page_config(page_title="CyberGuard AI - CVE Chatbot", layout="centered")

# Custom CSS untuk styling seperti contoh
st.markdown("""
<style>
    /* Main container styling */
    .main .block-container {
        padding-top: 2rem;
        max-width: 800px;
    }
    
    /* Chat message styling */
    .stChatMessage {
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 1rem;
    }
    
    /* User message styling */
    .stChatMessage[data-testid="user"] {
        background-color: #f0f2f6;
        border: 1px solid #e6e6e6;
    }
    
    /* Assistant message styling */
    .stChatMessage[data-testid="assistant"] {
        background-color: #ffffff;
        border: 1px solid #e6e6e6;
    }
    
    /* Chat input styling */
    .stChatInput > div > div {
        border-radius: 10px;
        border: 2px solid #e6e6e6;
        padding: 12px 16px;
        font-size: 16px;
    }
    
    /* Improve sidebar styling */
    .css-1d391kg {
        padding-top: 2rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
init_session_state()

# Header seperti contoh
st.title(" CYBERGUARD AI")
st.write("Ahli cybersecurity ready 24/7 untuk analisis kerentanan CVE dan keamanan sistem")
st.write("Sistem RAG canggih dengan data CVE terbaru dari NVD - Powered by Groq API & Llama 3.1")

# Tampilkan riwayat chat
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Input pengguna
if prompt := st.chat_input("Tanyakan tentang kerentanan cybersecurity atau CVE..."):
    # Tambahkan pesan user ke history
    st.session_state.messages.append({"role": "user", "content": prompt})
    
    # Tampilkan pesan user
    with st.chat_message("user"):
        st.markdown(prompt)

    # Tampilkan pesan assistant dengan streaming
    with st.chat_message("assistant"):
        response_container = st.empty()
        full_response = ""

        try:
            # Cari context yang relevan
            context_results = st.session_state.chatbot.cari_context_relevan(prompt)
            context_text = st.session_state.chatbot.format_context_untuk_prompt(context_results)

            # System prompt untuk cybersecurity expert
            system_prompt = f"""Anda adalah CyberGuard AI, ahli cybersecurity yang berpengalaman. Anda HANYA boleh menjawab berdasarkan informasi CVE yang disediakan.

INFORMASI CVE YANG TERSEDIA:
{context_text}

ATURAN:
1. Gunakan HANYA informasi dari context di atas
2. Jika informasi tidak ditemukan dalam context, jawab: 'Maaf, informasi tentang hal tersebut tidak tersedia dalam database CVE kami saat ini.'
3. Berikan jawaban yang profesional dan informatif
4. Fokus pada analisis keamanan dan rekomendasi mitigasi
5. Sertakan detail CVE ID ketika relevan"""

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]

            # Lakukan streaming respons dari model
            completion = st.session_state.chatbot.client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=messages,
                temperature=0.3,
                max_tokens=1024,
                top_p=1,
                stream=True,
            )

            # Stream response
            for chunk in completion:
                content = chunk.choices[0].delta.content or ""
                full_response += content
                response_container.markdown(full_response)

            # Tampilkan sumber context jika ada
            if context_results:
                with st.expander(" Sumber Informasi yang Digunakan", expanded=False):
                    for i, result in enumerate(context_results, 1):
                        st.markdown(f"**{i}. {result['metadata']['cve_id']}**")
                        st.caption(f"Severity: {result['metadata']['severity']} | Score: {result['metadata']['base_score']}")
                        st.caption(f"Similarity: {result['distance']:.4f}")

            # Tambahkan ke history
            st.session_state.messages.append({"role": "assistant", "content": full_response})

        except Exception as e:
            error_msg = f"Terjadi kesalahan saat menghubungi API: {e}"
            response_container.markdown(error_msg)
            st.session_state.messages.append({"role": "assistant", "content": error_msg})

# Sidebar untuk info tambahan
with st.sidebar:
    st.header("ℹ Tentang Sistem")
    st.markdown("""
    **CyberGuard AI** adalah sistem chatbot cybersecurity yang menggunakan:
    - **RAG Pipeline** dengan data CVE NVD
    - **Embedding Model**: all-MiniLM-L6-v2
    - **LLM**: Llama 3.1 8B Instant
    - **Vector Search**: Euclidean Distance
    
    **Fitur:**
     Analisis kerentanan CVE
    Pencarian semantik
     Rekomendasi mitigasi
     Update data real-time
    """)
    
    if st.session_state.chatbot:
        total_chunks = len(st.session_state.chatbot.data_embedding['chunk_texts'])
        st.metric("Total CVE Chunks", total_chunks)
    
    if st.button(" Hapus Percakapan"):
        st.session_state.messages = []
        st.rerun()