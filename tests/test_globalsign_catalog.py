import os
from pathlib import Path
from unittest.mock import patch, mock_open

import pytest

from app import globalsign_catalog as gc


# --------------------------------------------------------------------------
# Small fixture helpers
# --------------------------------------------------------------------------
FAKE_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIB\n"
    "-----END CERTIFICATE-----\n"
)

SMALL_CATALOG = [
    {
        "file": "dv_2025.pem",
        "label": "DV 2025",
        "validation": "DV",
        "algorithm": "RSA",
        "year": 2025,
        "description": "dv 2025",
    },
    {
        "file": "dv_2020.pem",
        "label": "DV 2020",
        "validation": "DV",
        "algorithm": "RSA",
        "year": 2020,
        "description": "dv 2020",
    },
    {
        "file": "ov_2025.pem",
        "label": "OV 2025",
        "validation": "OV",
        "algorithm": "ECC",
        "year": 2025,
        "description": "ov 2025",
    },
    {
        "file": "ev_2025.pem",
        "label": "EV 2025",
        "validation": "EV",
        "algorithm": "RSA",
        "year": 2025,
        "description": "ev 2025",
    },
]


@pytest.fixture()
def tmp_globalsign(tmp_path, monkeypatch):
    """Create a temp directory with fake .pem files and point GLOBALSIGN_DIR at it."""
    d = tmp_path / "globalsign_intermediates"
    d.mkdir()
    for entry in SMALL_CATALOG:
        (d / entry["file"]).write_text(FAKE_PEM)
    monkeypatch.setattr(gc, "GLOBALSIGN_DIR", str(d))
    return d


# ==========================================================================
# Module-level constants
# ==========================================================================
class TestModuleConstants:
    def test_globalsign_dir_is_absolute(self):
        assert os.path.isabs(gc.GLOBALSIGN_DIR)

    def test_globalsign_dir_ends_with_intermediates(self):
        assert gc.GLOBALSIGN_DIR.endswith("globalsign_intermediates")

    def test_catalog_is_list_of_dicts(self):
        assert isinstance(gc.GLOBALSIGN_CATALOG, list)
        assert gc.GLOBALSIGN_CATALOG
        for entry in gc.GLOBALSIGN_CATALOG:
            assert isinstance(entry, dict)

    def test_each_entry_has_required_keys(self):
        required = {"file", "label", "validation",
                    "algorithm", "year", "description"}
        for entry in gc.GLOBALSIGN_CATALOG:
            assert required.issubset(entry.keys()), entry

    def test_validation_values_are_known(self):
        allowed = {"DV", "OV", "EV"}
        for entry in gc.GLOBALSIGN_CATALOG:
            assert entry["validation"] in allowed

    def test_algorithm_values_are_known(self):
        allowed = {"RSA", "ECC"}
        for entry in gc.GLOBALSIGN_CATALOG:
            assert entry["algorithm"] in allowed

    def test_year_is_int(self):
        for entry in gc.GLOBALSIGN_CATALOG:
            assert isinstance(entry["year"], int)

    def test_file_names_end_with_pem(self):
        for entry in gc.GLOBALSIGN_CATALOG:
            assert entry["file"].endswith(".pem")

    def test_file_names_are_unique(self):
        names = [e["file"] for e in gc.GLOBALSIGN_CATALOG]
        assert len(names) == len(set(names))

    def test_validation_order_constant(self):
        assert gc._VALIDATION_ORDER == {"DV": 0, "OV": 1, "EV": 2}


# ==========================================================================
# load_catalog
# ==========================================================================
class TestLoadCatalog:
    def test_loads_all_files(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            items = gc.load_catalog()
        assert len(items) == len(SMALL_CATALOG)

    def test_item_has_id_and_pem(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            items = gc.load_catalog()
        by_file = {it["file"]: it for it in items}
        it = by_file["dv_2025.pem"]
        assert it["id"] == "dv_2025"
        assert it["pem"] == FAKE_PEM

    def test_id_replaces_pem_extension(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            items = gc.load_catalog()
        for it in items:
            assert not it["id"].endswith(".pem")
            assert it["id"] == it["file"][:-4]

    def test_original_entry_fields_preserved(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            items = gc.load_catalog()
        it = next(i for i in items if i["file"] == "dv_2025.pem")
        assert it["label"] == "DV 2025"
        assert it["validation"] == "DV"
        assert it["algorithm"] == "RSA"
        assert it["year"] == 2025
        assert it["description"] == "dv 2025"

    def test_missing_file_is_skipped(self, tmp_globalsign):
        # Remove one file from disk
        (Path(tmp_globalsign) / "ov_2025.pem").unlink()
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            items = gc.load_catalog()
        files = {i["file"] for i in items}
        assert "ov_2025.pem" not in files
        assert len(items) == len(SMALL_CATALOG) - 1

    def test_missing_file_does_not_raise(self, tmp_globalsign):
        # Entire directory missing
        with patch.object(gc, "GLOBALSIGN_DIR", "/does/not/exist"), \
             patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            items = gc.load_catalog()
        assert items == []

    def test_unreadable_file_is_skipped(self, tmp_globalsign):
        # Simulate read failure on the first file
        original_open = open

        def fake_open(path, *a, **kw):
            if str(path).endswith("dv_2025.pem"):
                raise PermissionError("denied")
            return original_open(path, *a, **kw)

        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG), \
             patch("builtins.open", side_effect=fake_open):
            items = gc.load_catalog()
        files = {i["file"] for i in items}
        assert "dv_2025.pem" not in files
        # Others loaded normally
        assert "dv_2020.pem" in files

    def test_empty_catalog_returns_empty_list(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", []):
            assert gc.load_catalog() == []

    def test_item_is_a_copy_not_the_original_entry(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            items = gc.load_catalog()
        original = next(e for e in SMALL_CATALOG if e["file"] == "dv_2025.pem")
        loaded = next(i for i in items if i["file"] == "dv_2025.pem")
        # Loading must not mutate the module-level entry dict
        assert "id" not in original
        assert "pem" not in original
        assert loaded is not original

    def test_pem_content_exact(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            items = gc.load_catalog()
        for it in items:
            assert it["pem"] == FAKE_PEM

    def test_real_catalog_does_not_crash(self, tmp_globalsign, monkeypatch):
        # Run against the real GLOBALSIGN_CATALOG with the fake directory:
        # all real files will be missing, so the result should be an empty list.
        items = gc.load_catalog()
        assert items == []


# ==========================================================================
# grouped_catalog
# ==========================================================================
class TestGroupedCatalog:
    def test_groups_present(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            groups = gc.grouped_catalog()
        names = [g["name"] for g in groups]
        assert names == ["DV", "OV", "EV"]

    def test_group_order_dv_ov_ev(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            groups = gc.grouped_catalog()
        assert [g["name"] for g in groups] == ["DV", "OV", "EV"]

    def test_items_grouped_correctly(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            groups = gc.grouped_catalog()
        by_name = {g["name"]: g["items"] for g in groups}
        assert {it["file"] for it in by_name["DV"]} == {
            "dv_2025.pem", "dv_2020.pem"
        }
        assert {it["file"] for it in by_name["OV"]} == {"ov_2025.pem"}
        assert {it["file"] for it in by_name["EV"]} == {"ev_2025.pem"}

    def test_items_sorted_by_year_desc_then_label(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            groups = gc.grouped_catalog()
        dv = next(g for g in groups if g["name"] == "DV")
        # Year 2025 first, then 2020
        assert [it["year"] for it in dv["items"]] == [2025, 2020]

    def test_ties_in_year_sorted_by_label(self, tmp_globalsign):
        catalog = [
            {"file": "a.pem", "label": "B", "validation": "DV",
             "algorithm": "RSA", "year": 2025, "description": ""},
            {"file": "b.pem", "label": "A", "validation": "DV",
             "algorithm": "RSA", "year": 2025, "description": ""},
        ]
        for e in catalog:
            (Path(tmp_globalsign) / e["file"]).write_text(FAKE_PEM)
        with patch.object(gc, "GLOBALSIGN_CATALOG", catalog):
            groups = gc.grouped_catalog()
        dv = next(g for g in groups if g["name"] == "DV")
        assert [it["label"] for it in dv["items"]] == ["A", "B"]

    def test_empty_groups_are_omitted(self, tmp_globalsign):
        # Only DV entries
        catalog = [
            {"file": "dv_2025.pem", "label": "DV 2025",
             "validation": "DV", "algorithm": "RSA",
             "year": 2025, "description": ""},
        ]
        with patch.object(gc, "GLOBALSIGN_CATALOG", catalog):
            groups = gc.grouped_catalog()
        assert [g["name"] for g in groups] == ["DV"]

    def test_other_group_for_unknown_validation(self, tmp_globalsign):
        catalog = [
            {"file": "x.pem", "label": "X",
             "validation": "XY", "algorithm": "RSA",
             "year": 2025, "description": ""},
            {"file": "y.pem", "label": "Y",
             "validation": "", "algorithm": "RSA",
             "year": 2025, "description": ""},
        ]
        for e in catalog:
            (Path(tmp_globalsign) / e["file"]).write_text(FAKE_PEM)
        with patch.object(gc, "GLOBALSIGN_CATALOG", catalog):
            groups = gc.grouped_catalog()
        names = [g["name"] for g in groups]
        assert names == ["Other"]
        other = groups[0]["items"]
        assert [it["label"] for it in other] == ["X", "Y"]

    def test_other_group_after_dv_ov_ev(self, tmp_globalsign):
        catalog = SMALL_CATALOG + [
            {"file": "z.pem", "label": "Z",
             "validation": "QQ", "algorithm": "RSA",
             "year": 2025, "description": ""},
        ]
        (Path(tmp_globalsign) / "z.pem").write_text(FAKE_PEM)
        with patch.object(gc, "GLOBALSIGN_CATALOG", catalog):
            groups = gc.grouped_catalog()
        assert [g["name"] for g in groups] == ["DV", "OV", "EV", "Other"]

    def test_lowercase_validation_normalized(self, tmp_globalsign):
        catalog = [
            {"file": "x.pem", "label": "X",
             "validation": "dv", "algorithm": "RSA",
             "year": 2025, "description": ""},
        ]
        (Path(tmp_globalsign) / "x.pem").write_text(FAKE_PEM)
        with patch.object(gc, "GLOBALSIGN_CATALOG", catalog):
            groups = gc.grouped_catalog()
        assert [g["name"] for g in groups] == ["DV"]

    def test_missing_validation_key_goes_to_other(self, tmp_globalsign):
        catalog = [
            {"file": "x.pem", "label": "X", "algorithm": "RSA",
             "year": 2025, "description": ""},
        ]
        (Path(tmp_globalsign) / "x.pem").write_text(FAKE_PEM)
        with patch.object(gc, "GLOBALSIGN_CATALOG", catalog):
            groups = gc.grouped_catalog()
        assert [g["name"] for g in groups] == ["Other"]

    def test_missing_year_defaults_to_zero(self, tmp_globalsign):
        catalog = [
            {"file": "a.pem", "label": "A",
             "validation": "DV", "algorithm": "RSA",
             "description": ""},
            {"file": "b.pem", "label": "B",
             "validation": "DV", "algorithm": "RSA",
             "year": 2025, "description": ""},
        ]
        for e in catalog:
            (Path(tmp_globalsign) / e["file"]).write_text(FAKE_PEM)
        with patch.object(gc, "GLOBALSIGN_CATALOG", catalog):
            groups = gc.grouped_catalog()
        dv = next(g for g in groups if g["name"] == "DV")
        # 2025 comes before missing (0)
        assert [it["label"] for it in dv["items"]] == ["B", "A"]

    def test_all_missing_files_returns_empty(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG), \
             patch.object(gc, "GLOBALSIGN_DIR", "/does/not/exist"):
            groups = gc.grouped_catalog()
        assert groups == []

    def test_each_group_has_name_and_items(self, tmp_globalsign):
        with patch.object(gc, "GLOBALSIGN_CATALOG", SMALL_CATALOG):
            groups = gc.grouped_catalog()
        for g in groups:
            assert set(g.keys()) >= {"name", "items"}
            assert isinstance(g["items"], list)

    def test_full_pipeline_with_real_catalog_and_fake_dir(self,
                                                          tmp_globalsign):
        assert gc.grouped_catalog() == []
