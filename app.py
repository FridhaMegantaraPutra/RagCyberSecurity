import streamlit as st
import pickle
import os
from dotenv import load_dotenv
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from groq import Groq

# Load environment variables
load_dotenv()

def cari_similaritas_cosine(query, data_embedding, top_k=3):
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
        
        # Load embeddings data 5 tahun
        try:
            with open('cve_embeddings_5tahun.pkl', 'rb') as file:
                self.data_embedding = pickle.load(file)
        except FileNotFoundError:
            st.error("File cve_embeddings_5tahun.pkl tidak ditemukan. Jalankan embedding script terlebih dahulu.")
            st.stop()
        except Exception as e:
            st.error(f"Error loading embeddings: {e}")
            st.stop()
    
    def cari_context_relevan(self, query, top_k=3):
        """
        Mencari context yang relevan berdasarkan query
        """
        try:
            results = cari_similaritas_cosine(query, self.data_embedding, top_k=top_k)
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
            context_text += f"  Deskripsi: {result['metadata']['full_description']}\n"
            context_text += f"  Published: {result['metadata']['published_date']}\n"
            if result['metadata']['weaknesses']:
                context_text += f"  Weaknesses: {', '.join(result['metadata']['weaknesses'][:3])}\n"
            context_text += f"  Similarity: {result['similarity']:.4f}\n\n"
        
        return context_text

def init_session_state():
    """
    Initialize session state untuk chatbot
    """
    if "messages" not in st.session_state:
        st.session_state.messages = []
    
    if "chatbot" not in st.session_state:
        with st.spinner("Memuat sistem cybersecurity dengan data CVE 5 tahun..."):
            st.session_state.chatbot = CVEChatbot()

# Konfigurasi halaman Streamlit
st.set_page_config(
    page_title="CyberGuard AI - CVE Chatbot", 
    layout="centered",
    page_icon="🛡️"
)

# Custom CSS untuk styling
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
    
    /* Header styling */
    .header-style {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        margin-bottom: 2rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
init_session_state()

# Header dengan styling yang lebih baik
st.markdown("""
<div class="header-style">
    <h1 style="margin:0; color:white;">CYBERGUARD AI</h1>
    <p style="margin:0; opacity:0.9;">Ahli cybersecurity ready 24/7 untuk analisis kerentanan CVE dan keamanan sistem</p>
    <p style="margin:0; font-size:0.9rem; opacity:0.8;">Sistem RAG canggih dengan data CVE 5 tahun dari NVD - Powered by Groq API & Llama 3.1</p>
</div>
""", unsafe_allow_html=True)

# Quick query suggestions
st.markdown("###  Contoh Pertanyaan")
col1, col2, col3 = st.columns(3)
with col1:
    if st.button("Apache Log4j", use_container_width=True):
        st.session_state.quick_query = "Apa vulnerability kritis yang mempengaruhi Apache Log4j?"
with col2:
    if st.button("Microsoft Exchange", use_container_width=True):
        st.session_state.quick_query = "CVE terbaru apa yang mempengaruhi Microsoft Exchange Server?"
with col3:
    if st.button("SQL Injection", use_container_width=True):
        st.session_state.quick_query = "Apakah ada vulnerability SQL injection kritis dalam sebulan terakhir?"

# Tampilkan riwayat chat
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Handle quick query
if "quick_query" in st.session_state:
    prompt = st.session_state.quick_query
    del st.session_state.quick_query
else:
    prompt = st.chat_input("Tanyakan tentang kerentanan cybersecurity atau CVE...")

if prompt:
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
            with st.spinner("Mencari informasi CVE yang relevan..."):
                context_results = st.session_state.chatbot.cari_context_relevan(prompt, top_k=5)
                context_text = st.session_state.chatbot.format_context_untuk_prompt(context_results)

            # System prompt untuk cybersecurity expert
            system_prompt = f"""Anda adalah CyberGuard AI, ahli cybersecurity yang berpengalaman. Anda HANYA boleh menjawab berdasarkan informasi CVE yang disediakan.

INFORMASI CVE YANG TERSEDIA:
{context_text}

ATURAN:
1. Gunakan HANYA informasi dari context di atas
2. Jika informasi tidak ditemukan dalam context, jawab: 'Maaf, informasi tentang hal tersebut tidak tersedia dalam database CVE 5 tahun kami saat ini.'
3. Berikan jawaban yang profesional dan informatif
4. Fokus pada analisis keamanan dan rekomendasi mitigasi
5. Sertakan detail CVE ID ketika relevan
6. Prioritaskan vulnerability dengan severity tinggi
7. Berikan konteks tahun publikasi jika relevan"""

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]

            # Lakukan streaming respons dari model
            with st.spinner("Menganalisis dan menghasilkan respons..."):
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
                with st.expander("🔍 Sumber Informasi yang Digunakan", expanded=False):
                    for i, result in enumerate(context_results, 1):
                        st.markdown(f"**{i}. {result['metadata']['cve_id']}**")
                        st.caption(f"Severity: {result['metadata']['severity']} | Score: {result['metadata']['base_score']}")
                        st.caption(f"Published: {result['metadata']['published_date']}")
                        st.caption(f"Similarity: {result['similarity']:.4f}")
                        if result['metadata']['weaknesses']:
                            st.caption(f"CWE: {', '.join(result['metadata']['weaknesses'][:2])}")

            # Tambahkan ke history
            st.session_state.messages.append({"role": "assistant", "content": full_response})

        except Exception as e:
            error_msg = f"Terjadi kesalahan saat memproses permintaan: {e}"
            response_container.markdown(error_msg)
            st.session_state.messages.append({"role": "assistant", "content": error_msg})

# Sidebar untuk info tambahan
with st.sidebar:
    st.header("ℹ Tentang Sistem")
    st.markdown("""
    **CyberGuard AI** adalah sistem chatbot cybersecurity yang menggunakan:
    - **RAG Pipeline** dengan data CVE NVD 5 tahun
    - **Embedding Model**: all-MiniLM-L6-v2
    - **LLM**: Llama 3.1 8B Instant
    - **Vector Search**: Cosine Similarity
    
    **Cakupan Data:**
    - CVE dari 5 tahun terakhir
    - Update berkala dari NVD
    - Analisis real-time
    """)
    
    if st.session_state.chatbot:
        total_chunks = len(st.session_state.chatbot.data_embedding['chunk_texts'])
        total_cve = st.session_state.chatbot.data_embedding.get('total_cve', 'N/A')
        st.metric("Total CVE", total_cve)
        st.metric("Total Chunks", total_chunks)
        
        # Tampilkan statistik singkat
        st.markdown("---")
        st.subheader(" Statistik Data")
        
        # Hitung distribusi severity dari metadata
        severities = {}
        for meta in st.session_state.chatbot.data_embedding['metadata']:
            severity = meta.get('severity', 'UNKNOWN')
            severities[severity] = severities.get(severity, 0) + 1
        
        for severity, count in severities.items():
            st.write(f"{severity}: {count} chunks")
    
    st.markdown("---")
    if st.button(" Hapus Percakapan"):
        st.session_state.messages = []
        st.rerun()
    
    # Informasi tambahan
    st.markdown("""
    **Supported Queries:**
    - Analisis vulnerability spesifik
    - Pencarian CVE berdasarkan teknologi
    - Rekomendasi mitigasi
    - Perbandingan severity
    - Trend keamanan
    """)

# Footer
st.markdown("---")
st.caption("CyberGuard AI v2.0 - Data CVE 5 Tahun | Powered by NVD API & Groq")