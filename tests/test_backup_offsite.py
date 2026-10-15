"""Off-site backups (V11.7): S3-compatible endpoint (Backblaze B2 etc.) is
used when set, and the outcome is recorded for the admin backup status."""
import sys
import types

import app as app_module


def _fake_boto(calls, fail=False):
    class _Client:
        def upload_file(self, path, bucket, key):
            if fail:
                raise RuntimeError("InvalidAccessKeyId")
            calls.append((bucket, key))
    mod = types.ModuleType("boto3")
    mod.client = lambda name, **kw: (calls.append(("client", kw)) or _Client())
    return mod


def test_offsite_upload_uses_endpoint_and_records_status(monkeypatch):
    calls = []
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto(calls))
    monkeypatch.setattr(app_module, "BACKUP_S3_BUCKET", "simply-backups")
    monkeypatch.setattr(app_module, "BACKUP_S3_ENDPOINT", "https://s3.us-west-004.backblazeb2.com")
    monkeypatch.setattr(app_module, "BACKUP_S3_REGION", "us-west-004")
    app_module._run_backup()
    assert calls[0] == ("client", {"endpoint_url": "https://s3.us-west-004.backblazeb2.com", "region_name": "us-west-004"})
    assert calls[1][0] == "simply-backups" and calls[1][1].startswith("backups/data_")
    assert app_module.load_json(app_module._BACKUP_OFFSITE_STATUS, {})["ok"] is True


def test_offsite_failure_is_recorded_not_silent(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto([], fail=True))
    monkeypatch.setattr(app_module, "BACKUP_S3_BUCKET", "simply-backups")
    app_module._run_backup()
    st = app_module.load_json(app_module._BACKUP_OFFSITE_STATUS, {})
    assert st["ok"] is False and "InvalidAccessKeyId" in st["error"]
