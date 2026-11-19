"""
KuantumCryptography_VDR_PQC_Protocol çalıştırma ve doğrulama senaryosu.
Kapsam: Araştırma, veri mahremiyeti ve siber mimari prototipi.
Klinik tanı, değerlendirme veya tedavi kararı niteliği taşımaz.
"""

import copy

from pqc_channel import PQCChannel
from profiles import ROLES, get_profile


def run_demo() -> None:
    sender_role = ROLES["authority"]
    receiver_role = ROLES["compute_node"]
    channel = PQCChannel(kem_scheme="ML-KEM-768", dsa_scheme="ML-DSA-65")

    print("=== Kuantum Cryptography VDR PQC Prototip Senaryosu ===")
    print(f"Gönderen : {sender_role}")
    print(f"Alıcı    : {receiver_role}\n")

    # Senaryo 1: Geçerli VDR_BASELINE_SIM profilinin güvenli aktarımı ve doğrulanması
    baseline_profile = get_profile("VDR_BASELINE_SIM")
    valid_envelope = channel.sign_envelope(
        sender=sender_role,
        receiver=receiver_role,
        profile_data=baseline_profile,
    )
    ok_1, msg_1, data_1 = channel.verify_and_open(receiver_role, valid_envelope)
    print("[Senaryo 1 - Geçerli Paket]")
    print(f"Durum: {ok_1} | Mesaj: {msg_1}")
    print(f"Doğrulanan Gen: {data_1['gene']} ({data_1['locus']})\n" if data_1 else "")

    # Senaryo 2: VDR_HIGH_VARIATION_SIM paketinde iletim sırasında değer değişikliği (tampering)
    high_var_profile = get_profile("VDR_HIGH_VARIATION_SIM")
    tampered_envelope = copy.deepcopy(channel.sign_envelope(
        sender=sender_role,
        receiver=receiver_role,
        profile_data=high_var_profile,
    ))
    # İletim hattında skorda izinsiz oynama yapıldığını simüle et
    tampered_envelope["payload"]["features"]["expression_norm"] = 0.99

    ok_2, msg_2, data_2 = channel.verify_and_open(receiver_role, tampered_envelope)
    print("[Senaryo 2 - Değiştirilmiş / Bozulmuş Paket]")
    print(f"Durum: {ok_2} | Mesaj: {msg_2}")
    print(f"Açılan Veri: {data_2}\n")


if __name__ == "__main__":
    run_demo()
