"""
KuantumCryptography_VDR_PQC_Protocol - Streamlit Etkileşimli Prototip Arayüzü.
Kapsam: Araştırma, veri mahremiyeti ve siber mimari doğrulaması.
Klinik tanı, değerlendirme veya tedavi kararı niteliği taşımaz.
"""

import copy
import streamlit as st

from pqc_channel import PQCChannel
from profiles import ROLES, VDR_PROFILES, get_profile

st.set_page_config(
    page_title="Kuantum Cryptography - VDR PQC Prototipi",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 Kuantum Cryptography — VDR PQC Prototipi")
st.caption(
    "Araştırma, veri mahremiyeti ve siber mimari doğrulaması amaçlı prototiptir; "
    "klinik tanı, değerlendirme veya tedavi kararı yerine geçmez."
)

col_left, col_right = st.columns([1, 1.3])

with col_left:
    st.subheader("1. Senaryo ve Parametre Seçimi")
    profile_id = st.selectbox("Sentetik VDR Profili", list(VDR_PROFILES.keys()))
    selected_profile = copy.deepcopy(get_profile(profile_id))

    kem_scheme = st.selectbox("Anahtar Kapsülleme (ML-KEM Mantığı)", ["ML-KEM-768", "ML-KEM-1024"])
    dsa_scheme = st.selectbox("İmzalama / Doğrulama (ML-DSA Mantığı)", ["ML-DSA-65", "ML-DSA-87"])

    simulate_tamper = st.checkbox(
        "İletim sırasında veride izinsiz değişiklik (tampering) simüle et",
        value=False,
    )

    modified_expr = selected_profile["features"]["expression_norm"]
    if simulate_tamper:
        modified_expr = st.slider(
            "Yolda değiştirilen expression_norm değeri",
            min_value=0.0,
            max_value=1.0,
            value=0.99,
            step=0.01,
        )

with col_right:
    st.subheader("2. PQC Oturum ve Bütünlük Doğrulaması")
    sender_role = ROLES["authority"]
    receiver_role = ROLES["compute_node"]

    st.write(f"**Gönderen:** {sender_role}")
    st.write(f"**Alıcı:** {receiver_role}")

    if st.button("Güvenli Zarf Gönder ve Doğrula", type="primary"):
        channel = PQCChannel(kem_scheme=kem_scheme, dsa_scheme=dsa_scheme)
        envelope = channel.sign_envelope(
            sender=sender_role,
            receiver=receiver_role,
            profile_data=selected_profile,
        )

        if simulate_tamper:
            envelope["payload"]["features"]["expression_norm"] = modified_expr

        ok, message, verified_data = channel.verify_and_open(receiver_role, envelope)

        if ok:
            st.success(f"✅ {message}")
            st.json(verified_data)
        else:
            st.error(f"🛑 {message}")
            st.info("Sıfır güven (Zero-Trust) kuralı gereği bozulmuş paket reddedildi.")
