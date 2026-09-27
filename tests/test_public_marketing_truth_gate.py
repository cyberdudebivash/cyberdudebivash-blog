from pathlib import Path

PUBLIC_MARKETING = (
    "revenue-cta-block.js","ux-controller.js","conversion-engine.js",
    "ai-monetization-engine.js","monetization.js","products.html","api.html",
)
FORBIDDEN = (
    "4,800+ security professionals",
    "join 4,800+",
    "join 2,400+ analysts",
    "3,800+ security pros",
    "48h pre-disclosure",
    "48-hour pre-disclosure",
    "48h before nvd",
    "48h before public release",
    "updated every 10 minutes",
    '<span class="val">2,400+</span><span class="lbl">downloads</span>',
    '<span class="val">4.9★</span><span class="lbl">avg rating</span>',
    '<span class="val">500+</span><span class="lbl">soc teams</span>',
)

def test_public_marketing_has_no_known_unsupported_release_claims():
    for path in PUBLIC_MARKETING:
        text=Path(path).read_text(encoding="utf-8").lower()
        for claim in FORBIDDEN:
            assert claim.lower() not in text, f"{path}: unsupported release claim remains: {claim}"
