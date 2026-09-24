"""Bounded public-probe transport behavior; no real HTTP or sleep."""
import io
import json
import sys
import unittest
from pathlib import Path
from datetime import datetime, timezone
from contextlib import redirect_stdout
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import check_blogger_public_delivery as probe


def throttled(delay='2', status=429):
    return HTTPError(probe.BASE, status, 'provider error', {'Retry-After': delay}, None)


def response():
    result = MagicMock()
    result.__enter__.return_value = result
    result.url = probe.BASE + '/'
    result.read.return_value = b'valid response'
    return result


class PublicRetryTests(unittest.TestCase):
    @patch.object(probe.time, 'sleep')
    @patch.object(probe, 'urlopen')
    def test_transient_429_retries_then_returns_real_response(self, open_url, sleep):
        open_url.side_effect = [throttled(), response()]
        self.assertEqual(probe.fetch(probe.BASE, 'feed'), 'valid response')
        self.assertEqual(open_url.call_count, 2)
        sleep.assert_called_once_with(2)

    @patch.object(probe.time, 'sleep')
    @patch.object(probe, 'urlopen')
    def test_persistent_429_is_bounded_and_fails(self, open_url, sleep):
        open_url.side_effect = [throttled() for _ in range(3)]
        with self.assertRaises(probe.ProbeTransportError) as caught:
            probe.fetch(probe.BASE, 'mobile')
        self.assertEqual((caught.exception.endpoint, caught.exception.http_status, caught.exception.attempts), ('mobile', 429, 3))
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(open_url.call_count, 3)

    @patch.object(probe.time, 'sleep')
    @patch.object(probe, 'urlopen')
    def test_long_retry_after_is_not_shortened(self, open_url, sleep):
        open_url.side_effect = throttled('120')
        with self.assertRaises(probe.ProbeTransportError) as caught:
            probe.fetch(probe.BASE, 'feed')
        self.assertEqual(caught.exception.reason, 'retry_after_exceeds_budget')
        self.assertEqual(open_url.call_count, 1)
        sleep.assert_not_called()

    def test_retry_after_date_and_invalid_value(self):
        now = datetime(2026, 9, 24, 10, tzinfo=timezone.utc)
        self.assertEqual(probe.retry_delay('Thu, 24 Sep 2026 10:00:30 GMT', 1, now), 30)
        self.assertEqual(probe.retry_delay('bad', 2, now), 10)

    @patch.object(probe.time, 'sleep')
    @patch.object(probe, 'urlopen')
    def test_401_never_retried(self, open_url, sleep):
        open_url.side_effect = throttled(status=401)
        with self.assertRaises(probe.ProbeTransportError) as caught:
            probe.fetch(probe.BASE)
        self.assertEqual(caught.exception.http_status, 401)
        sleep.assert_not_called()

    @patch.object(sys, 'argv', ['probe'])
    @patch.object(probe, 'fetch')
    def test_main_reports_endpoint_and_nonzero_without_recovery(self, fetch):
        fetch.side_effect = probe.ProbeTransportError('feed', 'retries_exhausted', 3, 429)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(probe.main(), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'BLOGGER_PUBLIC_RATE_LIMITED')
        self.assertEqual(result['endpoint'], 'feed')
        self.assertFalse(result['recovery_required'])

    def test_public_failure_alert_precedes_generator_recovery_alert(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/freshness-check.yml').read_text()
        alert = workflow.split('name: "Alert on unresolved monitor failure"')[1]
        self.assertLess(alert.index('steps.public_delivery.outcome'), alert.index('steps.freshness.outputs.recovery_required'))
        self.assertIn('id: public_delivery', workflow)


if __name__ == '__main__':
    unittest.main()
