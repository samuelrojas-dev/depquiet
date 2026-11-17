"""A License field that names no license falls back to the OSI classifiers.

python-dateutil publishes License "Dual License" with Apache and BSD classifiers;
0.47.2 reported it UNKNOWN and failed the license check. With several
classifiers, the first one used to win, so MIT listed before GPL read as MIT.
"""

from depquiet.license import LicenseRisk, _license_of, classify_license

APACHE = "License :: OSI Approved :: Apache Software License"
BSD = "License :: OSI Approved :: BSD License"
GPL3 = "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
MIT = "License :: OSI Approved :: MIT License"


def test_free_text_field_uses_the_classifiers() -> None:
    found = _license_of(None, "Dual License", [APACHE, BSD])
    assert found == "Apache-2.0 AND BSD-3-Clause"
    assert classify_license(found)[1] is LicenseRisk.LOW


def test_a_real_license_name_is_kept() -> None:
    assert _license_of(None, "MIT", [GPL3]) == "MIT"


def test_several_classifiers_never_understate_the_risk() -> None:
    found = _license_of(None, None, [MIT, GPL3])
    assert classify_license(found)[1] is LicenseRisk.HIGH


def test_unreadable_field_without_classifiers_stays_unknown() -> None:
    assert _license_of(None, "Dual License", []) == "Dual License"
    assert classify_license("Dual License")[1] is LicenseRisk.UNKNOWN


def test_pep639_expression_wins() -> None:
    assert _license_of("MIT OR Apache-2.0", "Dual License", [GPL3]) == "MIT OR Apache-2.0"
