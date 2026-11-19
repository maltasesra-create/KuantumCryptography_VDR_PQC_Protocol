"""
Kuantum sonrası kriptografi (PQC) oturum, imzalama ve bütünlük doğrulama modülü.
Kapsam: Araştırma ve siber mimari prototipi (ML-KEM / ML-DSA kavramsal akışı).
Klinik tanı, değerlendirme veya tedavi kararı niteliği taşımaz.
"""

import hashlib
import hmac
import json
import os
from typing import Any, Dict, Tuple


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    """Sözlük verisini tutarlı bayt dizisine çevirir."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class PQCChannel:
    """ML-KEM (anahtar kapsülleme) ve ML-DSA (imzalama/doğrulama) mantığını modelleyen kanal."""

    def __init__(self, kem_scheme: str = "ML-KEM-768", dsa_scheme: str = "ML-DSA-65") -> None:
        self.kem_scheme = kem_scheme
        self.dsa_scheme = dsa_scheme
        # Prototip amaçlı oturum/imza anahtar materyali (gerçek üretimde PQC kütüphanesi kullanılır)
        self._signing_secret = os.urandom(32)

    def establish_session_key(self, sender: str, receiver: str) -> Tuple[str, bytes]:
        """
        ML-KEM benzeri oturum anahtarı türetir.
        Dönüş: (kapsüllenmiş_anahtar_özeti, oturum_anahtarı)
        """
        ephemeral_entropy = os.urandom(32)
        context = f"{self.kem_scheme}:{sender}->{receiver}".encode("utf-8")
        session_key = hashlib.sha256(context + ephemeral_entropy).digest()
        encapsulated_token = hashlib.sha256(b"KEM_CT:" + ephemeral_entropy).hexdigest()[:24]
        return encapsulated_token, session_key

    def sign_envelope(self, sender: str, receiver: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """VDR profil paketini imzalayıp zarf (envelope) haline getirir."""
        kem_token, session_key = self.establish_session_key(sender, receiver)
        body_bytes = _canonical_bytes(profile_data)

        # Zarf bütünlüğü için oturum anahtarıyla MAC ve ML-DSA benzeri imza özeti üretilir
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
            "_session_key_ref": session_key.hex(),  # Simülasyon kolaylığı için prototip alanı
        }

    def verify_and_open(self, expected_receiver: str, envelope: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any] | None]:
        """Alıcı kimliğini, paket bütünlüğünü ve imzayı doğrular."""
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

        mac_ok = hmac.compare_digest(mac_tag, expected_mac)
        sig_ok = hmac.compare_digest(signature, expected_sig)

        if not (mac_ok and sig_ok):
            return False, "Bütünlük veya imza doğrulaması başarısız! Paket değiştirilmiş olabilir.", None

        return True, "PQC oturum ve imza doğrulaması başarılı.", payload
