"""
Catalog of GlobalSign intermediate certificates.

The PEM files live in ./globalsign_intermediates/ (one cert per file).
This module maps filenames to human-readable metadata and loads PEMs
lazily at startup.
"""

import logging
import os

logger = logging.getLogger(__name__)

GLOBALSIGN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "globalsign_intermediates",
)

# Metadata for every supported file.
#   file        - filename inside GLOBALSIGN_DIR
#   label       - human-readable name shown in the UI
#   validation  - DV / OV / EV (used for grouping)
#   algorithm   - RSA / ECC
#   year        - year the intermediate was issued
#   description - short explanation shown as a tooltip
GLOBALSIGN_CATALOG = [
    # --- DV ---
    {
        "file": "gs_r46_alphassl_ca_2025.pem",
        "label": "GlobalSign GCC R46 AlphaSSL CA 2025",
        "validation": "DV",
        "algorithm": "RSA",
        "year": 2025,
        "description": "AlphaSSL Domain Validated. Chains to GlobalSign Root R46.",
    },
    {
        "file": "gs_r6_alphassl_ca_2025.pem",
        "label": "GlobalSign GCC R6 AlphaSSL CA 2025",
        "validation": "DV",
        "algorithm": "RSA",
        "year": 2025,
        "description": "AlphaSSL Domain Validated. Chains to GlobalSign Root R6 (legacy).",
    },
    {
        "file": "gs_r46_dv_ca_2025.pem",
        "label": "GlobalSign RSA R46 DV CA 2025",
        "validation": "DV",
        "algorithm": "RSA",
        "year": 2025,
        "description": "Domain Validated. Chains to GlobalSign Root R46.",
    },
    {
        "file": "gs_e46_dv_ca_2025.pem",
        "label": "GlobalSign ECC E46 DV CA 2025",
        "validation": "DV",
        "algorithm": "ECC",
        "year": 2025,
        "description": "Domain Validated. Chains to GlobalSign Root E46.",
    },
    {
        "file": "gs_r3_dv_ca_2020.pem",
        "label": "GlobalSign RSA R3 DV CA 2020",
        "validation": "DV",
        "algorithm": "RSA",
        "year": 2020,
        "description": "Domain Validated. Chains to GlobalSign Root R3 (legacy).",
    },
    {
        "file": "gs_rsa_dv_ca_2018.pem",
        "label": "GlobalSign RSA DV CA 2018",
        "validation": "DV",
        "algorithm": "RSA",
        "year": 2018,
        "description": "Domain Validated, SHA-256, G2. Chains to GlobalSign Root R1.",
    },

    # --- OV ---
    {
        "file": "gs_r46_ov_ca_2025.pem",
        "label": "GlobalSign RSA R46 OV CA 2025",
        "validation": "OV",
        "algorithm": "RSA",
        "year": 2025,
        "description": "Organization Validated. Chains to GlobalSign Root R46.",
    },
    {
        "file": "gs_e46_ov_ca_2025.pem",
        "label": "GlobalSign ECC E46 OV CA 2025",
        "validation": "OV",
        "algorithm": "ECC",
        "year": 2025,
        "description": "Organization Validated. Chains to GlobalSign Root E46.",
    },
    {
        "file": "gs_ecc_ov_ca_2018.pem",
        "label": "GlobalSign ECC OV CA 2018",
        "validation": "OV",
        "algorithm": "ECC",
        "year": 2018,
        "description": "Organization Validated, ECC. Chains to GlobalSign Root E1/E2.",
    },
    {
        "file": "gs_rsa_ov_ca_2018.pem",
        "label": "GlobalSign RSA OV CA 2018",
        "validation": "OV",
        "algorithm": "RSA",
        "year": 2018,
        "description": "Organization Validated, SHA-256, G2. Chains to GlobalSign Root R1.",
    },

    # --- EV ---
    {
        "file": "gs_r46_ev_ca_2025.pem",
        "label": "GlobalSign RSA R46 EV CA 2025",
        "validation": "EV",
        "algorithm": "RSA",
        "year": 2025,
        "description": "Extended Validation. Chains to GlobalSign Root R46.",
    },
    {
        "file": "gs_e46_ev_ca_2025.pem",
        "label": "GlobalSign ECC E46 EV CA 2025",
        "validation": "EV",
        "algorithm": "ECC",
        "year": 2025,
        "description": "Extended Validation. Chains to GlobalSign Root E46.",
    },
    {
        "file": "gs_r3_ev_qwac_ca_2020.pem",
        "label": "GlobalSign RSA R3 EV QWAC CA 2020",
        "validation": "EV",
        "algorithm": "RSA",
        "year": 2020,
        "description": "EV QWAC (Qualified Website Authentication Certificate, EU). Chains to Root R3.",
    },
    {
        "file": "gs_e46_ev_qwac_ca_2020.pem",
        "label": "GlobalSign ECC E46 EV QWAC CA 2020",
        "validation": "EV",
        "algorithm": "ECC",
        "year": 2020,
        "description": "EV QWAC (Qualified Website Authentication Certificate, EU). Chains to Root E46.",
    },
    {
        "file": "gs_rsa_ev_ca_2020.pem",
        "label": "GlobalSign RSA EV CA 2020",
        "validation": "EV",
        "algorithm": "RSA",
        "year": 2020,
        "description": "Extended Validation, SHA-256, G2. Chains to GlobalSign Root R1.",
    },
]

_VALIDATION_ORDER = {"DV": 0, "OV": 1, "EV": 2}


def load_catalog() -> list:
    items = []
    for entry in GLOBALSIGN_CATALOG:
        path = os.path.join(GLOBALSIGN_DIR, entry["file"])
        if not os.path.isfile(path):
            logger.warning("[globalsign] missing file: %s", path)
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                pem = f.read()
        except Exception as e:
            logger.warning("[globalsign] cannot read %s: %s", path, e)
            continue

        item = dict(entry)
        item["id"] = entry["file"].replace(".pem", "")
        item["pem"] = pem
        items.append(item)

    return items


def grouped_catalog() -> list:
    items = load_catalog()
    buckets = {"DV": [], "OV": [], "EV": []}
    other = []

    for it in items:
        key = it.get("validation", "").upper()
        if key in buckets:
            buckets[key].append(it)
        else:
            other.append(it)

    groups = []
    for name in sorted(buckets, key=lambda k: _VALIDATION_ORDER.get(k, 99)):
        lst = sorted(buckets[name], key=lambda x: (-x.get("year", 0), x["label"]))
        if lst:
            groups.append({"name": name, "items": lst})

    if other:
        groups.append({
            "name": "Other",
            "items": sorted(other, key=lambda x: x["label"]),
        })

    return groups
