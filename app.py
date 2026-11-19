"""
KuantumCryptography_VDR_PQC_Protocol - Streamlit Arayüzü
Kapsam: Araştırma, veri mahremiyeti ve siber mimari doğrulaması.
Klinik tanı, değerlendirme veya tedavi kararı niteliği taşımaz.
"""

import copy
import hashlib
import hmac
import json
import os
from typing import Any, Dict, Tuple

import streamlit as st

ROLES = {
    "authority": "Yetkili Taraf / Veri Sahibi (Anahtar ve Profil Kaynağı)",
    "compute_node": "Analiz / Hesaplama Düğümü (Sıfır Güven / PQC Kanal Alıcısı)",
}

VDR_PROFILES = {
    "VDR_BASELINE_SIM": {
        "gene": "VDR",
        "locus": "12q13.11",
        "sample_type": "synthetic_research_profile",
        "features": {
            "variant_rs2228570_score": 0.42,
            "variant_rs1544410_score": 0.61,
            "expression_norm": 0.55,
        },
        "scope_note": "Research and architectural simulation only; not for clinical use.",
    },
    "VDR_HIGH_VARIATION_SIM": {
        "gene": "VDR",
        "locus": "12q13.11",
        "sample_type": "synthetic_research_profile",
        "features": {
            "variant_rs2228570_score": 0.83,
            "variant_rs1544410_score": 0.74,
            "expression_norm": 0.29,
        },
        "scope_note": "Research and architectural simulation only; not for clinical use.",
    },
}


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class PQCChannel:
    """ML-KEM ve ML-DSA mantığını simüle eden prototip kanal."""

    def __init__(self, kem_scheme: str = "ML-KEM-768", dsa_scheme: str = "ML-DSA-65") -> None:
        self.kem_scheme = kem_scheme
        self.dsa_scheme = dsa_scheme
        self._signing_secret = os.urandom(32)

    def establish_session_key(self, sender: str, receiver: str) -> Tuple[str, bytes]:
        ephemeral_entropy = os.urandom(32)
        context = f"{self.kem_scheme}:{sender}->{receiver}".encode("utf-8")
        session_key = hashlib.sha256(context + ephemeral_entropy).digest()
        encapsulated_token = hashlib.sha256(b"KEM_CT:" + ephemeral_entropy).hexdigest()[:24]
        return encapsulated_token, session_key

    def sign_envelope(self, sender: str, receiver: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        kem_token, session_key = self.establish_session_key(sender, receiver)
        body_bytes = _canonical_bytes(profile_data)
        mac_tag = hmac.new(session_key, body_bytes, hashlib.sha256).hexdigest()
        dsa_signature = hmac.new(
            self._signing_secret,
            f"{self.dsa_scheme}:".encode("utf-8") + body_bytes + mac_tag.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return {
            "sender": sender,
            "receiver": receiver,
            "kem_scheme": self.kem_scheme,
            "dsa_scheme": self.dsa_scheme,
            "kem_token": kem_token,
            "payload": profile_data,
            "mac_tag": mac_tag,
            "signature": dsa_signature,
            "_session_key_ref": session_key.hex(),
        }

    def verify_and_open(
        self, expected_receiver: str, envelope: Dict[str, Any]
    ) -> Tuple[bool, str, Dict[str, Any] | None]:
        if envelope.get("receiver") != expected_receiver:
            return False, "Alıcı kimliği eşleşmedi (Zero-Trust reddi).", None

        payload = envelope.get("payload")
        mac_tag = envelope.get("mac_tag", "")
        signature = envelope.get("signature", "")
        session_key_hex = envelope.get("_session_key_ref", "")

        if not isinstance(payload, dict) or not session_key_hex:
            return False, "Eksik veya bozuk zarf yapısı.", None

        body_bytes = _canonical_bytes(payload)
        session_key = bytes.fromhex(session_key_hex)

        expected_mac = hmac.new(session_key, body_bytes, hashlib.sha256).hexdigest()
        expected_sig = hmac.new(
            self._signing_secret,
            f"{self.dsa_scheme}:".encode("utf-8") + body_bytes + expected_mac.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not (hmac.compare_digest(mac_tag, expected_mac) and hmac.compare_digest(signature, expected_sig)):
            return False, "Bütünlük veya imza doğrulaması başarısız! Paket değiştirilmiş olabilir.", None

        return True, "PQC oturum ve imza doğrulaması başarılı.", payload


st.set_page_config(
    page_title="Kuantum Cryptography — VDR PQC Prototipi",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 Kuantum Cryptography — VDR PQC Prototipi")
st.caption(
    "Araştırma, veri mahremiyeti ve siber mimari doğrulaması amaçlı prototiptir; "
    "klinik tanı, değerlendirme veya tedavi kararı yerine geçmez."
)

col1, col2 = st.columns([1, 1.3])

with col1:
    st.subheader("1. VDR Profili ve PQC Ayarları")
    profile_id = st.selectbox("Profil Seçin", list(VDR_PROFILES.keys()))
    profile_data = copy.deepcopy(VDR_PROFILES[profile_id])

    kem_scheme = st.selectbox("Anahtar Kapsülleme (ML-KEM)", ["ML-KEM-768", "ML-KEM-1024"])
    dsa_scheme = st.selectbox("İmza / Bütünlük (ML-DSA)", ["ML-DSA-65", "ML-DSA-87"])

    tamper_enabled = st.checkbox("İletim sırasında veride değişiklik (tampering) simüle et", value=False)
    tampered_val = profile_data["features"]["expression_norm"]
    if tamper_enabled:
        tampered_val = st.slider("Bozulan expression_norm değeri", 0.0, 1.0, 0.99, 0.01)

with col2:
    st.subheader("2. Güvenli Kanal ve Doğrulama Ekranı")
    sender = ROLES["authority"]
    receiver = ROLES["compute_node"]
    st.write(f"**Gönderen:** {sender}")
    st.write(f"**Alıcı:** {receiver}")

    if st.button("Zarfı Gönder ve Doğrula", type="primary"):
        channel = PQCChannel(kem_scheme=kem_scheme, dsa_scheme=dsa_scheme)
        envelope = channel.sign_envelope(sender=sender, receiver=receiver, profile_data=profile_data)

        if tamper_enabled:
            envelope["payload"]["features"]["expression_norm"] = tampered_val

        ok, msg, verified = channel.verify_and_open(receiver, envelope)

        st.write(f"**KEM Token:** `{envelope['kem_token']}`")
        if ok:
            st.success(f"✅ {msg}")
            st.json(verified)
        else:
            st.error(f"🛑 {msg}")
            st.info("Sıfır güven (Zero-Trust) kuralı gereği bozulmuş paket reddedildi.")
