"""Regression checks for Blogger index excerpts and full report retention."""
from unittest.mock import MagicMock, patch

from automation.blogger_publisher import BloggerPublisher, with_index_jump_break
from automation.config import Config


def test_first_paragraph_becomes_index_excerpt_without_losing_report():
    report = '<p>Verified summary.</p><section>' + ('evidence ' * 15000) + '</section>'
    result = with_index_jump_break(report, 'Intel title')
    assert result.startswith('<p>Verified summary.</p><!--more-->')
    assert result.replace('<!--more-->', '') == report
    assert result.count('<!--more-->') == 1


def test_existing_jump_break_is_preserved():
    report = '<p>Editor excerpt.</p><!--more--><div>Full report</div>'
    assert with_index_jump_break(report, 'Intel title') == report


def test_missing_early_paragraph_uses_escaped_teaser():
    report = '<div>' + ('X' * 5000) + '</div>'
    result = with_index_jump_break(report, '<Threat & Defense>')
    assert result.startswith('<p class="cdb-index-excerpt">&lt;Threat &amp; Defense&gt;</p><!--more-->')
    assert result.endswith(report)


def test_publish_sends_prepared_artifact_byte_for_byte():
    cfg = Config()
    cfg.blogger_blog_id = '12345'
    publisher = BloggerPublisher(cfg)
    publisher._access_token = 'test-token'
    publisher._token_expiry = float('inf')
    response = MagicMock(status_code=200, ok=True)
    response.json.return_value = {'id': 'post-1', 'status': 'LIVE', 'url': 'https://cti.cyberdudebivash.in/2026/09/test.html'}
    original = '<p>Evidence summary.</p><div>' + ('report ' * 10000) + '</div>'
    report = with_index_jump_break(original, 'Test Intel')
    with patch('requests.post', return_value=response) as post:
        publisher.publish_post('Test Intel', report, ['Threat Intelligence'])
    sent = post.call_args.kwargs['json']['content']
    assert sent == report
    assert sent.replace('<!--more-->', '') == original
    assert sent.index('<!--more-->') < 4096
