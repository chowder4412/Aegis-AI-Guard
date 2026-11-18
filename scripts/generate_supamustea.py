from __future__ import annotations

from pathlib import Path
import time
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "data" / "raw" / "supabros"
OUTPUT_XLSX = OUTPUT_DIR / "supamustea.xlsx"


def generate_supabros_phish_detecter(
    n_records: int = 210000,
    seed: int = 2026,
    output_xlsx: Path = OUTPUT_XLSX,
) -> pd.DataFrame:
    rng = np.random.default_rng(seed)

    # 16 balanced classes: 95,000 benign + 115,000 across 15 modern phishing vectors
    base_classes = [
        ("Benign_Enterprise_Email", 0, 95000),
        ("AiTM_ReverseProxy_MFA_Bypass", 1, 11000),
        ("LLM_HyperPersonalized_SpearPhish", 1, 11000),
        ("OAuth2_DeviceCode_Consent_Phish", 1, 9500),
        ("Dynamic_QR_Quishing", 1, 9000),
        ("HTML_SVG_Canvas_Smuggling", 1, 8500),
        ("Subdomain_Takeover_CNAME_Phish", 1, 8000),
        ("OpenRedirect_TrustedDomain_Chain", 1, 8000),
        ("BEC_Executive_Wire_Fraud", 1, 8500),
        ("TOAD_Callback_Vishing_Hybrid", 1, 7500),
        ("Web3_WalletDrainer_Lure", 1, 6500),
        ("Calendar_ICS_Payload_Injection", 1, 6500),
        ("Deepfake_Executive_Media_Bait", 1, 6000),
        ("CloudShare_Doc_Credential_Harvest", 1, 6000),
        ("SupplyChain_Vendor_Invoice_Spoof", 1, 5000),
        ("SMS_Email_Gateway_Smishing_Bridge", 1, 4000),
    ]

    scale = n_records / 210000.0
    classes = [
        (name, label, max(1, int(round(cnt * scale))))
        for name, label, cnt in base_classes
    ]

    frames: list[pd.DataFrame] = []
    for attack_name, is_phish, count in classes:
        df = pd.DataFrame()
        df["attack_vector_class"] = [attack_name] * count
        df["is_phishing"] = np.full(count, is_phish, dtype=np.int8)

        # --- 1. Authentication & Transport Layer (Features 1-12) ---
        b = is_phish == 0
        df["spf_pass"] = rng.binomial(1, 0.98 if b else 0.34, count)
        df["dkim_pass"] = rng.binomial(1, 0.97 if b else 0.31, count)
        df["dmarc_align"] = rng.binomial(1, 0.96 if b else 0.22, count)
        df["bimi_verified"] = rng.binomial(1, 0.48 if b else 0.01, count)
        df["arc_chain_valid"] = rng.binomial(1, 0.85 if b else 0.28, count)
        df["mta_sts_enforced"] = rng.binomial(1, 0.88 if b else 0.19, count)
        df["dane_tlsa_present"] = rng.binomial(1, 0.42 if b else 0.03, count)
        df["return_path_mismatch"] = rng.binomial(1, 0.04 if b else 0.76, count)
        df["reply_to_domain_diff"] = rng.binomial(1, 0.06 if b else 0.72, count)
        df["received_hops_count"] = rng.integers(2, 6, count) if b else rng.integers(4, 14, count)
        df["smtp_tls_downgrade"] = rng.binomial(1, 0.01 if b else 0.38, count)
        df["x_mailer_anomalous"] = rng.binomial(1, 0.02 if b else 0.59, count)

        # --- 2. Domain, DNS & Infrastructure Telemetry (Features 13-25) ---
        df["domain_age_days"] = rng.integers(365, 6500, count) if b else rng.integers(0, 180, count)
        df["dns_ttl_seconds"] = rng.integers(300, 86400, count) if b else rng.integers(10, 300, count)
        df["fast_flux_ip_changes"] = rng.integers(0, 2, count) if b else rng.integers(2, 18, count)
        df["dangling_cname_risk"] = rng.binomial(1, 0.005 if b else 0.14, count)
        df["asn_reputation_score"] = np.round(
            rng.uniform(0.75, 1.0, count) if b else rng.uniform(0.02, 0.55, count), 4
        )
        df["bulletproof_hosting_flag"] = rng.binomial(1, 0.002 if b else 0.41, count)
        df["ssl_cert_age_days"] = rng.integers(60, 1000, count) if b else rng.integers(0, 21, count)
        df["lets_encrypt_auto_cert"] = rng.binomial(1, 0.25 if b else 0.84, count)
        df["mx_record_valid"] = rng.binomial(1, 0.99 if b else 0.61, count)
        df["whois_privacy_enabled"] = rng.binomial(1, 0.30 if b else 0.89, count)
        df["tld_abuse_index"] = np.round(
            rng.uniform(0.01, 0.22, count) if b else rng.uniform(0.45, 0.98, count), 4
        )
        df["subdomain_depth"] = rng.integers(0, 3, count) if b else rng.integers(1, 7, count)
        df["newly_observed_domain"] = rng.binomial(1, 0.01 if b else 0.68, count)

        # --- 3. URL, AiTM Proxy & OAuth2 Signals (Features 26-39) ---
        df["url_count"] = rng.integers(0, 6, count) if b else rng.integers(1, 15, count)
        df["homoglyph_similarity"] = np.round(
            rng.uniform(0.0, 0.12, count) if b else rng.uniform(0.45, 0.99, count), 4
        )
        df["punycode_xn_present"] = rng.binomial(1, 0.001 if b else 0.29, count)
        df["redirect_chain_hops"] = rng.integers(0, 2, count) if b else rng.integers(1, 8, count)
        df["open_redirect_abused"] = rng.binomial(1, 0.005 if b else 0.26, count)
        df["url_entropy_score"] = np.round(
            rng.uniform(2.1, 3.8, count) if b else rng.uniform(3.9, 5.6, count), 4
        )
        df["ip_literal_in_url"] = rng.binomial(1, 0.001 if b else 0.18, count)
        df["aitm_reverse_proxy_js"] = rng.binomial(1, 0.0 if b else 0.24, count)
        df["session_cookie_hook_flag"] = rng.binomial(1, 0.0 if b else 0.21, count)
        df["oauth2_device_code_uri"] = rng.binomial(1, 0.002 if b else 0.16, count)
        df["oauth2_high_priv_scopes"] = rng.integers(0, 1, count) if b else rng.integers(0, 6, count)
        df["cloud_storage_redirect"] = rng.binomial(1, 0.08 if b else 0.44, count)
        df["shortened_url_flag"] = rng.binomial(1, 0.04 if b else 0.49, count)
        df["url_anchor_text_mismatch"] = rng.binomial(1, 0.02 if b else 0.78, count)

        # --- 4. Payload, Smuggling & Multi-Modal Evasion (Features 40-52) ---
        df["qr_code_embedded"] = rng.binomial(1, 0.03 if b else 0.22, count)
        df["qr_url_domain_mismatch"] = rng.binomial(1, 0.002 if b else 0.19, count)
        df["html_svg_smuggling_blob"] = rng.binomial(1, 0.0 if b else 0.25, count)
        df["canvas_text_render_evasion"] = rng.binomial(1, 0.0 if b else 0.17, count)
        df["zero_width_unicode_count"] = rng.integers(0, 2, count) if b else rng.integers(0, 45, count)
        df["homoglyph_char_count"] = rng.integers(0, 1, count) if b else rng.integers(0, 22, count)
        df["hidden_css_display_none"] = rng.integers(0, 2, count) if b else rng.integers(1, 14, count)
        df["base64_payload_entropy"] = np.round(
            rng.uniform(1.0, 4.2, count) if b else rng.uniform(5.2, 7.9, count), 4
        )
        df["ics_calendar_invite_flag"] = rng.binomial(1, 0.05 if b else 0.15, count)
        df["web3_wallet_drainer_abi"] = rng.binomial(1, 0.0 if b else 0.11, count)
        df["macro_or_script_attach"] = rng.binomial(1, 0.005 if b else 0.33, count)
        df["html_to_text_ratio"] = np.round(
            rng.uniform(0.2, 1.8, count) if b else rng.uniform(2.5, 9.5, count), 4
        )
        df["external_tracking_pixel"] = rng.binomial(1, 0.18 if b else 0.74, count)

        # --- 5. AI Stylometry, Behavioral & Graph Context (Features 53-62) ---
        df["llm_ai_stylometry_prob"] = np.round(
            rng.uniform(0.02, 0.38, count) if b else rng.uniform(0.45, 0.99, count), 4
        )
        df["text_perplexity_score"] = np.round(
            rng.uniform(35.0, 95.0, count) if b else rng.uniform(10.0, 42.0, count), 3
        )
        df["sentence_burstiness"] = np.round(
            rng.uniform(0.45, 0.95, count) if b else rng.uniform(0.05, 0.48, count), 4
        )
        df["urgency_pressure_score"] = np.round(
            rng.uniform(0.0, 0.30, count) if b else rng.uniform(0.50, 1.0, count), 4
        )
        df["financial_wire_keywords"] = rng.integers(0, 2, count) if b else rng.integers(1, 9, count)
        df["credential_lure_keywords"] = rng.integers(0, 2, count) if b else rng.integers(2, 11, count)
        df["toad_callback_phone_flag"] = rng.binomial(1, 0.01 if b else 0.18, count)
        df["deepfake_media_link_flag"] = rng.binomial(1, 0.0 if b else 0.12, count)
        df["comm_graph_centrality"] = np.round(
            rng.uniform(0.55, 1.0, count) if b else rng.uniform(0.0, 0.25, count), 4
        )
        df["first_time_sender_flag"] = rng.binomial(1, 0.08 if b else 0.86, count)

        # --- Attack-Specific Signature Boosts for Multi-Class Separability ---
        if attack_name == "AiTM_ReverseProxy_MFA_Bypass":
            df["aitm_reverse_proxy_js"] = 1
            df["session_cookie_hook_flag"] = 1
        elif attack_name == "LLM_HyperPersonalized_SpearPhish":
            df["llm_ai_stylometry_prob"] = np.round(rng.uniform(0.88, 0.999, count), 4)
            df["sentence_burstiness"] = np.round(rng.uniform(0.02, 0.18, count), 4)
        elif attack_name == "OAuth2_DeviceCode_Consent_Phish":
            df["oauth2_device_code_uri"] = 1
            df["oauth2_high_priv_scopes"] = rng.integers(3, 8, count)
        elif attack_name == "Dynamic_QR_Quishing":
            df["qr_code_embedded"] = 1
            df["qr_url_domain_mismatch"] = 1
        elif attack_name == "HTML_SVG_Canvas_Smuggling":
            df["html_svg_smuggling_blob"] = 1
            df["canvas_text_render_evasion"] = 1
        elif attack_name == "Subdomain_Takeover_CNAME_Phish":
            df["dangling_cname_risk"] = 1
            df["subdomain_depth"] = rng.integers(3, 8, count)
        elif attack_name == "OpenRedirect_TrustedDomain_Chain":
            df["open_redirect_abused"] = 1
            df["redirect_chain_hops"] = rng.integers(3, 9, count)
        elif attack_name == "BEC_Executive_Wire_Fraud":
            df["financial_wire_keywords"] = rng.integers(5, 12, count)
            df["url_count"] = 0
        elif attack_name == "TOAD_Callback_Vishing_Hybrid":
            df["toad_callback_phone_flag"] = 1
            df["url_count"] = 0
        elif attack_name == "Web3_WalletDrainer_Lure":
            df["web3_wallet_drainer_abi"] = 1
        elif attack_name == "Calendar_ICS_Payload_Injection":
            df["ics_calendar_invite_flag"] = 1
        elif attack_name == "Deepfake_Executive_Media_Bait":
            df["deepfake_media_link_flag"] = 1
        elif attack_name == "CloudShare_Doc_Credential_Harvest":
            df["cloud_storage_redirect"] = 1
            df["credential_lure_keywords"] = rng.integers(5, 12, count)
        elif attack_name == "SupplyChain_Vendor_Invoice_Spoof":
            df["arc_chain_valid"] = 1
            df["reply_to_domain_diff"] = 1
        elif attack_name == "SMS_Email_Gateway_Smishing_Bridge":
            df["shortened_url_flag"] = 1
            df["x_mailer_anomalous"] = 1

        frames.append(df)

    # Combine, shuffle, and assign unique record IDs
    full_df = pd.concat(frames, ignore_index=True)
    full_df = full_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    full_df.insert(0, "record_id", [f"SBPD-{i:06d}" for i in range(1, len(full_df) + 1)])

    output_xlsx.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    print(f"Writing {len(full_df):,} rows x {full_df.shape[1]} cols to {output_xlsx} ...")
    import xlsxwriter

    workbook = xlsxwriter.Workbook(str(output_xlsx), {"constant_memory": True})
    worksheet = workbook.add_worksheet("supamustea")
    worksheet.write_row(0, 0, list(full_df.columns))
    for row_idx, row in enumerate(full_df.itertuples(index=False, name=None), start=1):
        worksheet.write_row(row_idx, 0, row)
    workbook.close()

    elapsed = time.time() - t0
    size_mb = output_xlsx.stat().st_size / (1024 * 1024)
    print(f"Saved {output_xlsx} ({size_mb:.2f} MB) in {elapsed:.1f}s! Shape: {full_df.shape}")
    return full_df


if __name__ == "__main__":
    df = generate_supabros_phish_detecter(n_records=210000)

    # Quick Decision Tree Validation Check
    X = df.drop(columns=["record_id", "is_phishing", "attack_vector_class"])
    y_bin = df["is_phishing"]
    y_multi = df["attack_vector_class"]

    X_train, X_test, yb_train, yb_test, ym_train, ym_test = train_test_split(
        X, y_bin, y_multi, test_size=0.20, stratify=y_multi, random_state=42
    )
    dt_bin = DecisionTreeClassifier(max_depth=12, random_state=42).fit(X_train, yb_train)
    dt_multi = DecisionTreeClassifier(max_depth=16, random_state=42).fit(X_train, ym_train)

    print(f"Binary Decision Tree Accuracy:      {accuracy_score(yb_test, dt_bin.predict(X_test)):.4%}")
    print(f"Multi-Class Decision Tree Accuracy: {accuracy_score(ym_test, dt_multi.predict(X_test)):.4%}")
    print("\nClassification Report (Binary):")
    print(classification_report(yb_test, dt_bin.predict(X_test), target_names=["Benign (0)", "Phishing (1)"]))
