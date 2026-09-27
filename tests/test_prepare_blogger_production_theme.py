from pathlib import Path
import scripts.prepare_blogger_production_theme as tool

def test_refuses_when_live_operator_export_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(tool,"SOURCE",tmp_path/"production-current.xml")
    monkeypatch.setattr(tool,"OUT",tmp_path/"candidate.xml")
    monkeypatch.setattr(tool,"SHA",tmp_path/"candidate.sha256")
    assert tool.main()==2
    assert not tool.OUT.exists()

def test_prepares_candidate_without_overwriting_live_baseline(tmp_path, monkeypatch):
    src=tmp_path/"production-current.xml";out=tmp_path/"candidate.xml";sha=tmp_path/"candidate.sha256"
    original='''<html><script type="application/ld+json">{"@type":"WebSite","@id":"https://cyberbivash.blogspot.com/#website","url":"https://cyberbivash.blogspot.com/"}</script><body>Real-time Indicators: 142,890+ Board SLA Compliance 99.4% Financial Risk Exposure $2.4M Active Managed Tenants 142 Tenants SOC 2 Type II mQGNBF+1234BCDEF</body></html>'''
    src.write_text(original,encoding="utf-8")
    monkeypatch.setattr(tool,"SOURCE",src);monkeypatch.setattr(tool,"OUT",out);monkeypatch.setattr(tool,"SHA",sha)
    assert tool.main()==0
    assert src.read_text(encoding="utf-8")==original
    candidate=out.read_text(encoding="utf-8")
    assert "cyberbivash.blogspot.com/#website" not in candidate
    assert "https://cti.cyberdudebivash.in/#website" in candidate
    assert "142,890+" not in candidate
    assert "SOC 2 Type II" not in candidate
    assert "mQGNBF+1234BCDEF" not in candidate
    assert len(sha.read_text().split()[0])==64
