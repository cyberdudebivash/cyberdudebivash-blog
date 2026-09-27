#!/usr/bin/env python3
"""Prepare an operator-exported *current live* Blogger theme for proof-first release.

This tool deliberately refuses historical repository exports. It only accepts
blogger-theme/production-current.xml, which must first be exported from the
Blogger dashboard. It creates a separate candidate file; it never overwrites
the operator baseline and never deploys to Blogger.
"""
from __future__ import annotations
import hashlib,re,sys
from pathlib import Path

SOURCE=Path("blogger-theme/production-current.xml")
OUT=Path("blogger-theme/production-candidate.xml")
SHA=Path("blogger-theme/production-candidate.sha256")
BLOCKED=(
 r"mQGNBF\+1234BCDEF[^<\r\n]*", r"4096R/BIVASH_NAYAK",
 r"Real-time\s+Indicators\s*:\s*142,890\+", r"Global\s+Threat\s+Level\s+88\.4",
 r"Board\s+SLA\s+Compliance\s+99\.4%", r"Financial\s+Risk\s+Exposure\s+\$2\.4M",
 r"Insured\s+Coverage\s*:\s*100%", r"Cyber\s+Insurance\s+Score\s+94/100",
 r"Active\s+Managed\s+Tenants\s+142\s+Tenants", r"Global\s+Tenant\s+Health\s+99\.98%[^<\r\n]*",
 r"Platform\s+Status\s*:\s*99\.99%\s+ONLINE", r"SOC\s*2\s*Type\s*II",
)
def main()->int:
 if not SOURCE.is_file():
  print(f"ERROR: export the actual live Blogger theme to {SOURCE} first",file=sys.stderr);return 2
 text=SOURCE.read_text(encoding="utf-8")
 changed=text
 for pattern in BLOCKED:
  changed=re.sub(pattern,"",changed,flags=re.I)
 changed=changed.replace("https://cyberbivash.blogspot.com/#website","https://cti.cyberdudebivash.in/#website")
 changed=changed.replace("https://cyberbivash.blogspot.com/\"","https://cti.cyberdudebivash.in/\"")
 remaining=[p for p in BLOCKED if re.search(p,changed,re.I)]
 if remaining:
  print("ERROR: blocked public trust claims remain after transformation",file=sys.stderr);return 1
 if "https://cyberbivash.blogspot.com/#website" in changed:
  print("ERROR: Blogspot WebSite identity remains",file=sys.stderr);return 1
 if "https://cti.cyberdudebivash.in/" not in changed:
  print("ERROR: CTI custom-domain identity missing",file=sys.stderr);return 1
 OUT.write_text(changed,encoding="utf-8")
 digest=hashlib.sha256(OUT.read_bytes()).hexdigest()
 SHA.write_text(f"{digest}  {OUT.name}\n",encoding="utf-8")
 print(f"CANDIDATE={OUT}");print(f"SHA256={digest}");return 0
if __name__=="__main__":raise SystemExit(main())
