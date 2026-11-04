"""Tests for scripts/fetch_last_success.py."""

import importlib.util
import io
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

_script_path = (
    Path(__file__).resolve().parent.parent / "scripts" / "fetch_last_success.py"
)
_spec = importlib.util.spec_from_file_location("fetch_last_success", _script_path)
assert _spec is not None and _spec.loader is not None
_fetch_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fetch_mod)

fetch_last_successful_run = _fetch_mod.fetch_last_successful_run
main = _fetch_mod.main


class TestFetchLastSuccessfulRun:
    def test_missing_repo_returns_none(self, monkeypatch):
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        assert fetch_last_successful_run(repo=None) is None

    def test_success_response(self, monkeypatch):
        mock_response_data = {
            "workflow_runs": [
                {
                    "id": 12345,
                    "run_started_at": "2026-11-01T00:03:21Z",
                    "status": "completed",
                    "conclusion": "success",
                }
            ]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        monkeypatch.setattr(
            urllib.request, "urlopen", MagicMock(return_value=mock_resp)
        )

        res = fetch_last_successful_run(
            repo="owner/repo", token="dummy-token", workflow_name="crl-pages.yml"
        )
        assert res == datetime(2026, 11, 1, 0, 3, 21, tzinfo=UTC)

    def test_empty_runs_returns_none(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"workflow_runs": []}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        monkeypatch.setattr(
            urllib.request, "urlopen", MagicMock(return_value=mock_resp)
        )

        res = fetch_last_successful_run(repo="owner/repo")
        assert res is None

    def test_http_error_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            urllib.request,
            "urlopen",
            MagicMock(
                side_effect=urllib.error.HTTPError(
                    url="https://api.github.com",
                    code=403,
                    msg="Forbidden",
                    hdrs={},
                    fp=io.BytesIO(b""),
                )
            ),
        )
        res = fetch_last_successful_run(repo="owner/repo")
        assert res is None

    def test_network_error_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            urllib.request,
            "urlopen",
            MagicMock(side_effect=urllib.error.URLError("Network connection failed")),
        )
        res = fetch_last_successful_run(repo="owner/repo")
        assert res is None


class TestFetchLastSuccessCLI:
    def test_cli_outputs_timestamp_and_github_output(
        self, monkeypatch, capsys, tmp_path
    ):
        output_file = tmp_path / "github_output.txt"
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
        monkeypatch.setattr(
            "sys.argv",
            ["fetch_last_success.py", "--repo", "owner/repo"],
        )

        mock_response_data = {
            "workflow_runs": [
                {
                    "run_started_at": "2026-11-01T00:03:21Z",
                }
            ]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_response_data).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        monkeypatch.setattr(
            urllib.request, "urlopen", MagicMock(return_value=mock_resp)
        )

        main()

        captured = capsys.readouterr()
        assert "2026-11-01T00:03:21+00:00" in captured.out
        assert output_file.exists()
        assert "timestamp=2026-11-01T00:03:21+00:00" in output_file.read_text(
            encoding="utf-8"
        )

    def test_cli_no_run_outputs_empty(self, monkeypatch, capsys, tmp_path):
        output_file = tmp_path / "github_output.txt"
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
        monkeypatch.setattr(
            "sys.argv",
            ["fetch_last_success.py", "--repo", "owner/repo"],
        )

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"workflow_runs": []}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        monkeypatch.setattr(
            urllib.request, "urlopen", MagicMock(return_value=mock_resp)
        )

        main()

        captured = capsys.readouterr()
        assert captured.out == ""
        assert output_file.exists()
        assert "timestamp=\n" in output_file.read_text(encoding="utf-8")
