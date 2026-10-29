"""Shared lifecycle, platform selection and extension contract regressions."""
import contextlib
import dataclasses
import io
import json
from unittest.mock import patch

import pytest

from zbtriage import readers, report, cli
from zbtriage.context import ScanContext
from zbtriage.result import ModuleResult, Hit, EV_EXECUTION, EV_INVENTORY
from test_followup_fixes import bundle
from test_expanded_capabilities import context
from reader_fixtures import stub_registered_readers


@pytest.mark.parametrize("platform,required,excluded", [
    ("win32", {"host", "traces", "windows-execution"}, {"unix-host", "android", "ios"}),
    # The host reader runs everywhere for the hosts file; its Windows-only
    # checks are not run or reported on macOS and Linux.
    ("linux", {"unix-host", "host"}, {"traces", "windows-execution"}),
    ("darwin", {"unix-host", "host"}, {"traces", "windows-execution"}),
])
def test_platform_selection_source_and_bundle(bundle, platform, required, excluded):
    for api in (readers, bundle):
        names = {spec.name for spec in api.reader_select(context(), platform)}
        assert required <= names
        assert not excluded & names
        assert {"browser", "hash"} <= names


def test_targeted_does_not_select_live_host_readers(bundle, tmp_path):
    for api in (readers, bundle):
        for platform in ("win32", "linux", "darwin"):
            names = {spec.name for spec in api.reader_select(context(targets=(str(tmp_path),)), platform)}
            assert names == {"browser", "hash", "windows-execution"}


def test_phone_selection_and_optional_pattern_independence(bundle, tmp_path):
    for api in (readers, bundle):
        assert {spec.name for spec in api.reader_select(context(phone_path=str(tmp_path), patterns=True))} == {"android", "android-intrusion"}
    (tmp_path / "Manifest.plist").write_text("fixture marker only")
    for api in (readers, bundle):
        assert [spec.name for spec in api.reader_select(context(phone_path=str(tmp_path)))] == ["ios"]


def test_validation_rejects_ambiguous_or_input_controlled_registration(bundle):
    for api in (readers, bundle):
        spec = api.READER_SPECS[0]
        for specs in ((spec, spec), (dataclasses.replace(spec, module="../user_plugin"),),
                      (dataclasses.replace(spec, helpers=("../escape.py",)),),
                      (dataclasses.replace(spec, catalogue={}),)):
            with pytest.raises(ValueError):
                api.reader_validate(specs)


@pytest.mark.parametrize("cancel", [False, True])
def test_shared_lifecycle_preserves_partial_and_stops_on_cancel(bundle, cancel):
    for api in (readers, bundle):
        ctx = context()
        result_type = bundle.ModuleResult if api is bundle else ModuleResult
        hit_type = bundle.Hit if api is bundle else Hit
        calls = []
        def resolve(spec):
            def run(ctx):
                calls.append(spec.name)
                r = result_type(spec.name)
                ctx.partial = r
                r.add_hit(hit_type("fixture.invalid", "fixture", "fixture", evidence="referenced"))
                if len(calls) == 1:
                    if cancel:
                        raise KeyboardInterrupt
                    raise ValueError("late fixture error")
                return r
            return run
        result = api.reader_run(ctx, resolve)
        assert result[0].hits
        assert any(not c.ran for c in result[0].checks)
        assert (len(calls) == 1) == cancel


def test_invalid_result_and_import_failure_are_gaps(bundle):
    for api in (readers, bundle):
        def missing(spec):
            raise ImportError("fixture absent reader")
        result = api.reader_run(context(), missing)
        assert result and all(any(not c.ran for c in r.checks) for r in result)
        result = api.reader_run(context(), lambda spec: lambda ctx: None)
        assert all("invalid result" in r.checks[0].reason for r in result)


def test_coverage_is_derived_and_detached(bundle):
    for api in (readers, bundle):
        data = api.reader_catalogue()
        for spec in api.READER_SPECS:
            assert spec.name in data[spec.name]["check_kinds"]
            for key, value in spec.catalogue.items():
                if key == "check_kinds":
                    assert value.items() <= data[spec.name][key].items()
                else:
                    assert data[spec.name][key] == value
        data[api.READER_SPECS[0].name]["check_kinds"].clear()
        assert api.reader_catalogue()[api.READER_SPECS[0].name]["check_kinds"]


def test_all_registered_bundle_readers_are_stubbed(bundle):
    with contextlib.ExitStack() as stack:
        names = stub_registered_readers(stack, bundle)
        assert set(names) == {spec.name for spec in bundle.READER_SPECS}
        for spec in bundle.READER_SPECS:
            assert getattr(bundle, "run_" + spec.suffix)(context()).checks[0].name == "fixture"


def test_new_grades_never_claim_file_contents_or_execution_from_inventory():
    assert "contents" in report.EVIDENCE_MEANING[EV_EXECUTION]
    assert "does not prove execution" in report.EVIDENCE_MEANING[EV_INVENTORY]
    assert "HISTORICAL" in report.EVIDENCE_HEADLINE[EV_INVENTORY]
    description = report.describe_document()
    assert description["schema_version"] == "1.6"
    assert description["readers"] == readers.reader_describe()


def test_optional_absence_is_not_a_clean_check_and_cannot_hide_failures():
    result = ModuleResult("windows-execution", inapplicable_reason="No artifact selected")
    assert result.status == "NOT_APPLICABLE"
    assert not result.checks
    result.could_not_run("windows-prefetch", "unreadable input")
    assert result.status == "UNKNOWN"
    result.add_hit(Hit("fixture.exe", "fixture", "fixture", evidence=EV_EXECUTION))
    assert result.status == "HITS"
