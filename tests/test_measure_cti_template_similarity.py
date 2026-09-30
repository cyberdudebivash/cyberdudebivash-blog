"""Offline tests for scripts/measure_cti_template_similarity.py (issue #219 KPI tool)."""

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "measure_cti_template_similarity",
    Path(__file__).resolve().parents[1] / "scripts" / "measure_cti_template_similarity.py",
)
m = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(m)

TPL = '<div class="post-body">{}</div><div class="post-footer">x</div>'
COMMON = " ".join(["alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu"] * 5)


def test_templated_posts_score_high_and_distinct_posts_score_zero():
    pages = {
        "a": TPL.format(COMMON + " unique one two three four five six seven"),
        "b": TPL.format(COMMON + " other words entirely here now then fine"),
        "c": TPL.format("completely different analysis about another subject with many specific words indeed"),
    }
    r = m.measure(list(pages), fetcher=lambda u: pages[u])
    pc = r["pairwise_containment"]
    assert pc["min"] == 0.0
    assert pc["max"] >= 0.6
    shares = {p["url"]: p["boilerplate_share"] for p in r["posts"]}
    assert shares["c"] == 0.0 and shares["a"] >= 0.5


def test_scripts_and_styles_are_excluded_from_body_text():
    html = TPL.format("<script>var tracking = 1;</script><style>.x{}</style>real words only here")
    assert m.post_words(html) == ["real", "words", "only", "here"]
