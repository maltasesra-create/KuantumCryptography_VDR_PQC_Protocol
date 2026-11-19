"""
VDR (Vitamin D Receptor) gen profili senaryoları ve taraf/rol tanımları.
Kapsam: Araştırma, veri mahremiyeti ve siber mimari doğrulaması.
Klinik tanı, değerlendirme veya tedavi kararı niteliği taşımaz.
"""

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


def get_profile(profile_id: str) -> dict:
    """Tanımlı sentetik VDR araştırma profilini döndürür."""
    if profile_id not in VDR_PROFILES:
        raise KeyError(f"Bilinmeyen profil: {profile_id}")
    return VDR_PROFILES[profile_id]
