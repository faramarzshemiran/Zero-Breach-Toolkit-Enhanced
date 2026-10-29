"""Text patterns for 'worth a look' leads. DATA ONLY.

These patterns DESCRIBE commands an attacker gets people to run (download
tools, script hosts). They are never executed. They live here, outside the scan
modules, so the guard that forbids any module from naming a network tool
(tests/test_netguard.py) stays strict and simple. tests/test_heuristics.py pins
that this file imports nothing but `re` and calls nothing.
"""

import re

# A command that fetches or runs something from the web. Both halves must match.
RUNNER = re.compile(r"\b(powershell|pwsh|mshta|curl|wget|bitsadmin|certutil|msiexec|"
                    r"rundll32|regsvr32|wscript|cscript|cmd)\b", re.I)
REMOTE = re.compile(r"(https?://|ftp://|\\\\[^\\\s]|\b\d{1,3}(?:\.\d{1,3}){3}\b)", re.I)

# PowerShell download-and-run ("cradle"): something that runs text as code AND
# something that downloads it, in the same script block.
CRADLE_RUN = re.compile(r"\b(iex|invoke-expression)\b", re.I)
CRADLE_GET = re.compile(r"(downloadstring|downloaddata|invoke-webrequest|\biwr\b|"
                        r"invoke-restmethod|\birm\b|net\.webclient|start-bitstransfer)", re.I)
