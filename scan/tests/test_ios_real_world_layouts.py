"""Shapes seen in real iPhone backups and sysdiagnose archives that synthetic
fixtures had not covered: live databases whose recorded size differs from the
copied payload, contentless system messages, device-management settings files,
app files that only share a crash-report name, macOS AppleDouble files,
memory-pressure and stackshot reports, location client keys and unrelated
Cache.db stores."""
import contextlib
import io
import json
import plistlib
import sqlite3
import tarfile

import pytest

from zbtriage.context import ScanContext
from zbtriage.iocs import IocSet, Indicator
from zbtriage.modules import ios
from test_followup_fixes import bundle
from test_ios_upgrade import backup, db_bytes

DOMAIN = "realworld.invalid"
PROCESS = "realworldd"
LONG_PROCESS = "RealWorldTelemetryClientRegistrationService"
APP = "com.realworld.app"
PROFILE = "com.realworld.profile"


@pytest.fixture(params=("source", "bundle"))
def reader(request, bundle):
    return ios.run if request.param == "source" else bundle.run_ios


def ctx(root, kind="backup", password=""):
    indicators = [Indicator(DOMAIN, "fixture", "primary", "domain", "fixture"),
                  Indicator(PROCESS, "fixture", "primary", "process", "fixture"),
                  Indicator(LONG_PROCESS, "fixture", "primary", "process", "fixture"),
                  Indicator(APP, "fixture", "primary", "app-id", "fixture"),
                  Indicator(PROFILE, "fixture", "primary", "profile-id", "fixture")]
    return ScanContext(IocSet(indicators, "fixture", None), phone_path=str(root), ios_input=kind,
                       backup_password=password, emit=lambda _: None)


def gaps(result):
    return {c.name: c.reason for c in result.checks if not c.ran}


def _resize_record(root, relative, size):
    """Give one encrypted artifact a recorded Size that differs from its payload,
    as iOS does for a database that changes while the backup is made."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    path = root / "Manifest.db"
    plain = Cipher(algorithms.AES(b"m" * 32), modes.CBC(bytes(16))).decryptor()
    raw = plain.update(path.read_bytes()) + plain.finalize()
    work = root.parent / "manifest-edit.db"
    work.write_bytes(raw[:-raw[-1]])
    with contextlib.closing(sqlite3.connect(work)) as con:
        blob = con.execute("SELECT file FROM Files WHERE relativePath=?", (relative,)).fetchone()[0]
        metadata = plistlib.loads(blob)
        metadata["$objects"][1]["Size"] = size
        con.execute("UPDATE Files SET file=? WHERE relativePath=?",
                    (plistlib.dumps(metadata, fmt=plistlib.FMT_BINARY), relative))
        con.commit()
    raw = work.read_bytes()
    pad = 16 - len(raw) % 16
    enc = Cipher(algorithms.AES(b"m" * 32), modes.CBC(bytes(16))).encryptor()
    path.write_bytes(enc.update(raw + bytes([pad]) * pad) + enc.finalize())


@pytest.mark.parametrize("delta", (8192, -4096))
def test_encrypted_live_database_with_a_different_recorded_size(tmp_path, reader, delta):
    pytest.importorskip("cryptography")
    raw, _ = db_bytes(tmp_path, "CREATE TABLE ZPROCESS(ZPROCNAME)", [("INSERT INTO ZPROCESS VALUES(?)", (PROCESS,))])
    root = tmp_path / "backup"
    backup(root, [("WirelessDomain", "Library/Databases/DataUsage.sqlite", raw)], encrypted=True)
    _resize_record(root, "Library/Databases/DataUsage.sqlite", len(raw) + delta)
    result = reader(ctx(root, password="owner-password"))
    assert any(h.indicator == PROCESS for h in result.hits)
    assert "ios:processes" not in gaps(result)


def test_system_message_without_any_content_is_not_a_gap(tmp_path, reader):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me,attributedBody,item_type)",
                      [("INSERT INTO message VALUES(NULL,0,0,NULL,4)", ()),
                       ("INSERT INTO message VALUES(?,0,0,NULL,0)", ("see https://" + DOMAIN,))])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw)])
    result = reader(ctx(root))
    assert any(h.indicator == DOMAIN for h in result.hits)
    assert "ios:messages" not in gaps(result)


def test_device_management_files_profiles_and_events(tmp_path, reader):
    folder = "Library/ConfigurationProfiles/"
    files = [
        ("ProfileTruth.plist", {}),
        ("MCSettingsEvents.plist", {"SystemSettings": {}, "Restrictions": {}}),
        ("PublicInfo/MCMeta.plist", {"LastMigratedBuild": "22A3354"}),
        ("profile-0123abcd.stub", {"PayloadIdentifier": PROFILE, "PayloadType": "Configuration"}),
        ("MCProfileEvents.plist", {"ProfileEvents": [{PROFILE: {"operation": "install",
                                                                "process": "/usr/libexec/mobileconfig"}}]}),
    ]
    root = tmp_path / "backup"
    backup(root, [("SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles", folder + name,
                   plistlib.dumps(doc)) for name, doc in files])
    result = reader(ctx(root))
    grades = {(h.indicator, h.evidence) for h in result.hits}
    assert {(PROFILE, "configured"), (PROFILE, "device-log")} <= grades
    assert not {"ios:profiles", "ios:profile-events", "ios:profile-settings"} & set(gaps(result))


def test_app_files_named_like_crash_reports_are_not_crash_reports(tmp_path, reader):
    root = tmp_path / "backup"
    backup(root, [("AppDomain-com.example.vault", "Library/invalidWriteDetection.crash", b"A" * 64)])
    result = reader(ctx(root))
    assert "ios:crashes" not in gaps(result)


def _sysdiagnose(tmp_path, members):
    path = tmp_path / "sysdiagnose.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members:
            info = tarfile.TarInfo("sysdiagnose_fixture/" + name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def _ips(meta, body):
    return (json.dumps(meta) + "\n" + (json.dumps(body, indent=2) if isinstance(body, dict) else body)).encode()


def test_diagnostic_report_kinds(tmp_path, reader):
    jetsam = _ips({"bug_type": "298", "timestamp": "2026-01-02 03:04:05.00 +0000"},
                  {"processes": [{"name": PROCESS}, {"name": LONG_PROCESS[:32]}], "largestProcess": PROCESS})
    stackshot = _ips({"bug_type": "288"}, {"processByPid": {"7": {"procname": PROCESS}}})
    cpu = _ips({"bug_type": "202"}, "Date/Time: 2026-01-02\nCommand:          " + PROCESS + "\nPath:  /usr/libexec/x\n")
    feedback = _ips({"bug_type": "313"}, {"session": "no process identity here"})
    archive = _sysdiagnose(tmp_path, [
        ("crashes_and_spins/JetsamEvent-2026-01-02-030405.ips", jetsam),
        ("crashes_and_spins/stacks-2026-01-02-030405.ips", stackshot),
        ("crashes_and_spins/realworldd.cpu_resource-2026-01-02.ips", cpu),
        ("crashes_and_spins/SiriSearchFeedback-2026-01-02.ips", feedback),
        ("crashes_and_spins/._JetsamEvent-2026-01-02-030405.ips", b"\x00\x05\x16\x07\xa6\xab" * 20),
        ("logs/BatteryBDC/BDC_Daily_2026-01-02_03:04:05.csv", b"battery,1\n"),
    ])
    result = reader(ctx(archive, "sysdiagnose"))
    found = {h.indicator for h in result.hits}
    assert {PROCESS, LONG_PROCESS} <= found
    assert any(h.indicator == LONG_PROCESS and "truncated" in h.detail for h in result.hits)
    assert gaps(result) == {}


def test_truncated_names_need_the_full_width(tmp_path, reader):
    short = _ips({"bug_type": "298"}, {"processes": [{"name": LONG_PROCESS[:20]}]})
    archive = _sysdiagnose(tmp_path, [("crashes_and_spins/JetsamEvent-1.ips", short)])
    result = reader(ctx(archive, "sysdiagnose"))
    assert not any(h.indicator == LONG_PROCESS for h in result.hits)


def test_location_client_keys_and_unrelated_cache_stores(tmp_path, reader):
    clients = {"MigrationVersionNumber": 12.0,
               "i" + APP + ":": {"BundleId": APP, "Authorized": True},
               "p/System/Library/LocationBundles/Fixture.bundle:": {"BundlePath": "/System/Library/x"}}
    unrelated, _ = db_bytes(tmp_path, "CREATE TABLE admin(k,v); CREATE TABLE event_cache(e)")
    cache, _ = db_bytes(tmp_path, "CREATE TABLE cfurl_cache_response(request_key,time_stamp)",
                        [("INSERT INTO cfurl_cache_response VALUES(?,0)", ("https://" + DOMAIN + "/a",))])
    root = tmp_path / "backup"
    backup(root, [("RootDomain", "Library/Caches/locationd/clients.plist", plistlib.dumps(clients)),
                  ("HomeDomain", "Library/Caches/com.apple.rtcreporting/eventcache/Cache.db", unrelated),
                  ("HomeDomain", "Library/Caches/com.apple.Safari/Cache.db", cache)])
    result = reader(ctx(root))
    assert any(h.indicator == APP and "clients.plist" in h.location for h in result.hits)
    assert any(h.indicator == DOMAIN and "Cache.db" in h.location for h in result.hits)
    assert not {"ios:location-clients", "ios:url-cache"} & set(gaps(result))


PS_HEADER = ("USER             UID PRSNA   PID  PPID        F  %CPU %MEM PRI NI      VSZ    RSS WCHAN    TT  STAT "
             "STARTED      TIME COMMAND")


def test_sysdiagnose_process_list_and_installation_log(tmp_path, reader):
    # Right-aligned columns of varying width: the command does not start at the
    # header's COMMAND offset on every line.
    ps = "\n".join([
        PS_HEADER,
        "root               0     -     1     0     4004   0.0  0.6  37  0 407968288  11504 -        ??  Ss    "
        "5:46PM   0:12.00 /sbin/launchd",
        "mobile           501   199   777     1  4004004   0.0  0.1  31  0 4079087    1104 -        ??  S     "
        "6:36PM   0:00.01 /private/var/db/" + PROCESS + " --serve",
        "mobile           501   199   778     1  4004004   0.0  0.1  31  0 40790873361 1104 -        ??  S     "
        "6:36PM   0:00.01 /Applications/Real World.app/Real World -x",
    ]) + "\n"
    install = ("Tue May  2 10:40:14 2023 [4253] <notice> (0x16b103000) -[MIInstaller performInstallationWithError:]: "
               "Install Successful for (Developer:" + APP + "); Staging: 0.02s\n"
               "Tue May  2 10:40:17 2023 [4253] <notice> (0x16b21b000) -[MIInstaller performInstallationWithError:]: "
               "Installing <MIInstallableBundle ID=" + APP + "; Version=1.0, ShortVersion=1.0>\n")
    archive = _sysdiagnose(tmp_path, [("ps.txt", ps.encode()),
                                      ("logs/MobileInstallation/mobile_installation.log.0", install.encode())])
    result = reader(ctx(archive, "sysdiagnose"))
    running = [h for h in result.hits if h.indicator == PROCESS]
    assert running and all(h.evidence == "on-device" and "ps.txt" in h.location for h in running)
    assert any(h.indicator == APP and h.evidence == "device-log" and "mobile_installation" in h.location
               for h in result.hits)
    assert any(APP in lead.what and "developer build" in lead.what for lead in result.leads)
    assert gaps(result) == {}


def test_spaced_application_path_in_process_list(tmp_path, reader):
    path = "/Applications/Real World.app/Real World"
    ps = PS_HEADER + "\nmobile 501 199 778 1 4004004 0.0 0.1 31 0 4079 1104 - ?? S 6:36PM 0:00.01 " + path + " -x\n"
    archive = _sysdiagnose(tmp_path, [("ps.txt", ps.encode())])
    indicators = [Indicator(path, "fixture", "primary", "file-path", "fixture")]
    result = reader(ScanContext(IocSet(indicators, "fixture", None), phone_path=str(archive),
                                ios_input="sysdiagnose", emit=lambda _: None))
    assert any(h.indicator == path for h in result.hits)


def test_tcc_client_and_calendar_participant(tmp_path, reader):
    tcc, _ = db_bytes(tmp_path, "CREATE TABLE access(service,client,client_type,auth_value)",
                      [("INSERT INTO access VALUES('kTCCServiceLiverpool',?,1,2)", (PROCESS,)),
                       ("INSERT INTO access VALUES('kTCCServiceCamera',?,1,0)", ("/private/var/tmp/" + PROCESS,))])
    calendar, _ = db_bytes(tmp_path, "CREATE TABLE CalendarItem(summary,description,url,start_date);"
                                     "CREATE TABLE Participant(email,comment)",
                           [("INSERT INTO Participant VALUES(?,NULL)", ("someone@" + DOMAIN,)),
                            ("INSERT INTO Participant VALUES(NULL,NULL)", ())])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/TCC/TCC.db", tcc),
                  ("HomeDomain", "Library/Calendar/Calendar.sqlitedb", calendar)])
    result = reader(ctx(root))
    grades = {(h.indicator, h.evidence) for h in result.hits if "TCC.db" in h.location}
    assert {(PROCESS, "configured"), (PROCESS, "referenced")} <= grades
    assert any(h.indicator == DOMAIN and "Calendar" in h.location for h in result.hits)
    assert not {"ios:permissions", "ios:calendar"} & set(gaps(result))


def test_backup_without_manifest_plist_is_read_as_unencrypted(tmp_path, reader):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE ZPROCESS(ZPROCNAME)", [("INSERT INTO ZPROCESS VALUES(?)", (PROCESS,))])
    root = tmp_path / "backup"
    backup(root, [("WirelessDomain", "Library/Databases/DataUsage.sqlite", raw)])
    (root / "Manifest.plist").unlink()
    result = reader(ctx(root))
    assert any(h.indicator == PROCESS for h in result.hits)
    assert "Manifest.plist is missing" in gaps(result).get("ios:manifest", "")


def test_stix_file_name_holding_a_path_is_a_path(tmp_path):
    from zbtriage.stix import load_stix
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "malware", "id": "malware--1", "name": "Fixture", "is_family": False},
        {"type": "indicator", "id": "indicator--1", "pattern_type": "stix",
         "pattern": "[file:name='/var/fixture/thing']", "valid_from": "2026-01-01T00:00:00Z"},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1"}]}), encoding="utf-8")
    loaded = load_stix(str(path), source="fixture")
    assert [(i.value, i.type) for i in loaded.indicators] == [("/var/fixture/thing", "file-path")]


def test_installed_profile_inside_an_archive(tmp_path, reader):
    archive = _sysdiagnose(tmp_path, [
        ("ConfigurationProfiles/profile-0123abcd.stub", plistlib.dumps({"PayloadIdentifier": PROFILE}))])
    result = reader(ctx(archive, "sysdiagnose"))
    assert any(h.indicator == PROFILE and h.evidence == "configured" for h in result.hits)


def test_diagnostic_record_caps_are_reported(tmp_path, reader):
    names = [{"name": "proc%d" % n} for n in range(5000)] + [{"name": PROCESS}]
    jetsam = _ips({"bug_type": "298"}, {"processes": names})
    archive = _sysdiagnose(tmp_path, [("crashes_and_spins/JetsamEvent-1.ips", jetsam)])
    result = reader(ctx(archive, "sysdiagnose"))
    assert "more than 5,000 processes" in gaps(result).get("ios:crashes", "")


def test_encrypted_backup_with_empty_payloads(tmp_path, reader):
    # iCloud Drive files whose content is only in iCloud are listed with an
    # empty payload; that is not a damaged backup.
    pytest.importorskip("cryptography")
    raw, _ = db_bytes(tmp_path, "CREATE TABLE ZPROCESS(ZPROCNAME)", [("INSERT INTO ZPROCESS VALUES(?)", (PROCESS,))])
    root = tmp_path / "backup"
    backup(root, [("WirelessDomain", "Library/Databases/DataUsage.sqlite", raw),
                  ("HomeDomain", "Library/Preferences/.GlobalPreferences.plist", b"")], encrypted=True)
    import hashlib
    fid = hashlib.sha1(b"HomeDomain-Library/Preferences/.GlobalPreferences.plist").hexdigest()
    (root / fid[:2] / fid).write_bytes(b"")
    _resize_record(root, "Library/Preferences/.GlobalPreferences.plist", 0)
    result = reader(ctx(root, password="owner-password"))
    assert any(h.indicator == PROCESS for h in result.hits)
    assert not any("damaged" in reason for reason in gaps(result).values())


def test_malformed_connection_record_does_not_stop_later_artifacts(tmp_path, reader):
    import json as _json
    good = _json.dumps({"net": {"http_server_properties": {"servers": [{"server": "https://" + DOMAIN + ":443"}]}}})
    bad = _json.dumps({"net": ["unexpected"]})
    root = tmp_path / "backup"
    backup(root, [("AppDomain-com.example.a", "Library/Application Support/A/Network Persistent State", bad.encode()),
                  ("AppDomain-com.example.b", "Library/Application Support/B/Network Persistent State", good.encode())])
    result = reader(ctx(root))
    assert any(h.indicator == DOMAIN and h.evidence == "contacted" for h in result.hits)
    assert "ios:browser-connections" in gaps(result)
