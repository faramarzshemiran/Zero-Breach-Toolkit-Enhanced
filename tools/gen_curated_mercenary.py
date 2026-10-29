"""Generate iocs/curated_mercenary.txt (tab-separated). Every value below was read
from the raw text of the cited Citizen Lab report (2026-10-25), not a summary."""
import io
import sys

OUT = sys.argv[1]
P1 = "citizenlab-paragon-2025-03"   # 'Virtue or Vice? A First Look at Paragon's Proliferating Spyware Operations'
P2 = "citizenlab-paragon-2025-06"   # 'Graphite Caught: First Forensic Confirmation of Paragon's iOS Mercenary Spyware ...'
FAM = "Paragon Graphite"

header = """# Curated mercenary-spyware indicators not available in any machine-readable feed
# as-of: 2026-10-25
# ^ Curated date; the staleness reference for this file.
# Licence: CC0 1.0 (as iocs/LICENSE.md). Indicators are facts; the citations below
#   name the researchers who published them.
# Method: every value was read out of the raw text of the cited report (not from a
#   summary), and its ROLE is recorded from the report's own description.
# Format: indicator <TAB> tier <TAB> confidence <TAB> source-tag <TAB> family
#
# Sources
#   citizenlab-paragon-2025-03  The Citizen Lab, 'Virtue or Vice? A First Look at Paragon's
#       Proliferating Spyware Operations' (2025-03-19).
#       https://citizenlab.ca/research/a-first-look-at-paragons-proliferating-spyware-operations/
#   citizenlab-paragon-2025-06  The Citizen Lab, 'Graphite Caught: First Forensic Confirmation of
#       Paragon's iOS Mercenary Spyware Finds Journalists Targeted' (2025-06-12).
#       https://citizenlab.ca/research/first-forensic-confirmation-of-paragons-ios-mercenary-spyware-finds-journalists-targeted/
#
# NOT included, deliberately:
#   - customer-deployment IPs the report publishes only partially (e.g. 67.69.21.xxx);
#   - certificate name 'forti.external-Sht_prd_2.com' (not a valid hostname: underscore);
#   - BIGPRETZEL / SMALLPRETZEL: named forensic indicators whose values are not published.
#"""

rows = []
def add(value, tier, src, note=None):
    if note:
        rows.append("# " + note)
    rows.append("\t".join([value, tier, "primary", src, FAM]))

rows.append("#")
rows.append("# --- Tier 1: victim-facing Graphite servers (devices are expected to contact these)")
add("46.183.184.91", "infrastructure-ip", P2,
    "Server the journalist's iPhone contacted (Jan-Feb 2025, iOS 18.2.1); rented from EDIS Global;"
    " matched Paragon Fingerprint P1 until at least 2025-04-12. Links both cases to one operator.")
add("84.110.122.27", "infrastructure-ip", P1,
    "Tier 1 IP (Fingerprint P1) that also returned cert CN=forti.external-Staging-02.com, Jul-Sep 2023.")
add("178.237.39.204", "infrastructure-ip", P1,
    "Tier 1 IP (Fingerprint P1) that later returned cert CN=awake-wood.io.")
add("awake-wood.io", "infrastructure", P1, "Certificate name seen on Tier 1 IP 178.237.39.204.")
add("forti.external-staging-02.com", "infrastructure", P1,
    "Certificate name seen on Tier 1 IP 84.110.122.27 (lower-cased).")
rows.append("#")
rows.append("# --- Tier 2: Paragon / customer premises (operator side). Ordinary devices are NOT expected")
rows.append("#     to contact these; the names are certificate common names and may not resolve in DNS.")
rows.append("#     Static IPs in Israel that returned Tier 2 certificates (Table 2):")
for last in (82, 83, 84, 85, 86):
    add("84.110.47.%d" % last, "infrastructure-ip", P1)
add("forti.paraccess.com", "infrastructure", P1, "Tier 2 certificate names on the Israeli IPs (Table 2):")
add("modern-money.org", "infrastructure", P1)
add("ancient-thing.it", "infrastructure", P1)
rows.append("#     Certificate names on suspected customer deployments (codename initial matches country):")
for name in ("external-astra.com", "internal-abba.com", "external-cap.com", "external-drt.com",
             "forti.external-muki.com", "external-cag.com", "forti.external-sht.com",
             "forti.external-shotgun3.com", "forti.external-sht-prd-4.com", "forti.internal-stg.com"):
    add(name, "infrastructure", P1)

with io.open(OUT, "w", encoding="utf-8", newline="\n") as fh:
    fh.write(header + "\n" + "\n".join(rows) + "\n")
print("wrote", OUT, sum(1 for r in rows if not r.startswith("#")), "indicators")
