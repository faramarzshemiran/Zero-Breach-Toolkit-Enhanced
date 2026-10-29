"""Authored COM interfaces and event records; never query the host's protection."""
import ctypes
import types

import pytest

from zbtriage import security_products
from zbtriage.modules import traces
from zbtriage.result import ModuleResult
from test_followup_fixes import bundle
from test_traces import ctx


@pytest.fixture(params=("source", "bundle"))
def av_api(request, bundle):
    return bundle if request.param == "bundle" else security_products


class ComFixture:
    def __init__(self):
        self.keep = []
        self.released = []
        self.freed = []
        self.lengths = {}

    def interface(self, methods, label):
        convention = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
        table = (ctypes.c_void_p * 10)()
        methods = dict(methods)
        methods[2] = ((), lambda _self: self.released.append(label) or 0)
        for slot, (args, function) in methods.items():
            callback = convention(ctypes.c_int32, ctypes.c_void_p, *args)(function)
            self.keep.append(callback)
            table[slot] = ctypes.cast(callback, ctypes.c_void_p).value
        pointer = ctypes.pointer(ctypes.cast(table, ctypes.POINTER(ctypes.c_void_p)))
        self.keep.extend((table, pointer))
        return ctypes.cast(pointer, ctypes.c_void_p)

    def product(self, name, state=0, signature=1, failure=None):
        buffer = ctypes.create_unicode_buffer(name)
        address = ctypes.addressof(buffer)
        self.keep.append(buffer)
        self.lengths[address] = len(name)

        def put_name(_self, out):
            out[0] = address
            return -2147467259 if failure == "name" else 0

        def put_state(_self, out):
            out[0] = state
            return -2147467259 if failure == "state" else 0

        def put_signature(_self, out):
            out[0] = signature
            return -2147467259 if failure == "signature" else 0

        return self.interface({
            7: ((ctypes.POINTER(ctypes.c_void_p),), put_name),
            8: ((ctypes.POINTER(ctypes.c_int32),), put_state),
            9: ((ctypes.POINTER(ctypes.c_int32),), put_signature),
        }, name)

    def product_list(self, products, count=None):
        def get_count(_self, out):
            out[0] = len(products) if count is None else count
            return 0

        def get_item(_self, index, out):
            out[0] = products[index].value
            return 0

        return self.interface({
            8: ((ctypes.POINTER(ctypes.c_int32),), get_count),
            9: ((ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)), get_item),
        }, "list")

    def SysStringLen(self, pointer):
        return self.lengths.get(pointer.value, 0)

    def SysFreeString(self, pointer):
        self.freed.append(pointer.value)


@pytest.mark.parametrize("vendor", ("Bitdefender", "ESET Security", "Norton", "Microsoft Defender", "Unlisted vendor"))
def test_native_vtables_read_any_registered_vendor_and_free_resources(av_api, vendor):
    fixture = ComFixture()
    pointer = fixture.product_list([fixture.product(vendor)])
    products, error = av_api._av_read_products(pointer, fixture)
    assert products == [{"name": vendor, "state": 0, "signature_status": 1}]
    assert not error
    assert fixture.released == [vendor] and len(fixture.freed) == 1


@pytest.mark.parametrize("failure,state,signature,name", (
    ("name", 0, 1, "Bad"), ("state", 0, 1, "Bad"), ("signature", 0, 1, "Bad"),
    (None, 4, 1, "Bad"), (None, 0, 2, "Bad"), (None, 0, 1, ""),
    (None, 0, 1, "x" * 4097),
))
def test_partial_inventory_keeps_good_product_and_uncertainty(av_api, failure, state, signature, name):
    fixture = ComFixture()
    pointer = fixture.product_list([fixture.product(name, state, signature, failure), fixture.product("Good")])
    products, error = av_api._av_read_products(pointer, fixture)
    assert [p["name"] for p in products] == ["Good"] and error
    assert fixture.released == [name, "Good"] and len(fixture.freed) == 2


@pytest.mark.parametrize("count", (-1, 129, 2147483647))
def test_product_count_is_bounded_before_item_access(av_api, count):
    fixture = ComFixture()
    with pytest.raises(OSError, match="count"):
        av_api._av_read_products(fixture.product_list([], count), fixture)
    assert not fixture.released and not fixture.freed


@pytest.mark.parametrize("state", (0, 1, 2, 3))
@pytest.mark.parametrize("signature", (0, 1))
def test_report_distinguishes_current_state_from_historical_defender_event(monkeypatch, av_api, state, signature):
    api = traces if av_api is security_products else av_api
    monkeypatch.setattr(api, "_tr_antivirus_products", lambda: ([{"name": "Bitdefender", "state": state, "signature_status": signature}], ""))
    monkeypatch.setattr(api, "_tr_events", lambda *a, **k: ([{"Id": 5001, "Time": "2020-01-01", "Data": {}}], ""))
    result = ModuleResult("traces")
    leads = api._TrLeads(result)
    protection = api._tr_check_antivirus(result, leads)
    api._tr_check_defender(result, ctx(), leads, protection)
    leads.finish()
    assert not result.hits
    assert result.submetrics["antivirus_products_on"] == int(state == 0)
    historical_leads = [lead for lead in result.leads if "Defender history" in lead.what]
    assert bool(historical_leads) is (state != 0)
    assert any("outdated protection updates" in lead.what for lead in result.leads) is (state == 0 and signature == 0)
    assert any("Bitdefender" in note for note in result.notes)
    assert all(check.ran for check in result.checks)


@pytest.mark.parametrize("partial", (False, True))
def test_unavailable_inventory_is_gap_even_with_partial_active_product(monkeypatch, av_api, partial):
    api = traces if av_api is security_products else av_api
    products = [{"name": "Bitdefender", "state": 0, "signature_status": 1}] if partial else []
    monkeypatch.setattr(api, "_tr_antivirus_products", lambda: (products, "Security Center unavailable"))
    result = ModuleResult("traces")
    leads = api._TrLeads(result)
    protection = api._tr_check_antivirus(result, leads)
    leads.finish()
    assert not protection["complete"]
    assert any(not check.ran and check.name == "antivirus-status" for check in result.checks)
    assert not result.hits and not result.leads


def test_empty_inventory_does_not_claim_no_antivirus_is_installed(monkeypatch, av_api):
    api = traces if av_api is security_products else av_api
    monkeypatch.setattr(api, "_tr_antivirus_products", lambda: ([], ""))
    result = ModuleResult("traces")
    leads = api._TrLeads(result)
    api._tr_check_antivirus(result, leads)
    leads.finish()
    assert len(result.leads) == 1 and not result.hits
    assert "did not report" in result.leads[0].what
    assert "do not register" in result.leads[0].usual_reason


def test_platform_or_library_failure_returns_uncertainty_without_activation(monkeypatch, av_api):
    monkeypatch.setattr(av_api.sys, "platform", "linux")
    assert av_api.antivirus_products()[1]
    monkeypatch.setattr(av_api.sys, "platform", "win32")
    loads = []

    def denied(name, **kwargs):
        loads.append((name, kwargs))
        raise OSError("fixture failure")

    monkeypatch.setattr(av_api.ctypes, "WinDLL", denied, raising=False)
    products, error = av_api.antivirus_products()
    assert not products and "fixture failure" in error
    assert loads == [("ole32.dll", {"winmode": 0x800})]


@pytest.mark.parametrize("initialize", (0, 1, -2147417850, -2147467259))
@pytest.mark.parametrize("fail_create", (False, True))
def test_secure_native_activation_balances_com_lifetime(monkeypatch, av_api, initialize, fail_create):
    calls, loads = [], []

    class Function:
        def __init__(self, function):
            self.function = function

        def __call__(self, *args):
            return self.function(*args)

    def class_object(clsid, iid, output):
        calls.append(("class", bytes(clsid), bytes(iid)))
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = 11
        return 0

    ole = types.SimpleNamespace(
        CoInitializeEx=Function(lambda *a: initialize),
        CoUninitialize=Function(lambda: calls.append("uninitialize")),
    )
    automation = types.SimpleNamespace(SysStringLen=Function(lambda _: 0), SysFreeString=Function(lambda _: None))
    wsc = types.SimpleNamespace(DllGetClassObject=Function(class_object))

    def load(name, **kwargs):
        loads.append((name, kwargs))
        return {"ole32.dll": ole, "oleaut32.dll": automation, "wscapi.dll": wsc}[name]

    def method(pointer, slot, *arguments):
        def invoke(_self, *args):
            if slot == 2:
                calls.append(("release", pointer.value))
            elif pointer.value == 11 and slot == 3:
                assert args[0] is None
                calls.append(("create", bytes(args[1])))
                if fail_create:
                    return -2147467259
                ctypes.cast(args[2], ctypes.POINTER(ctypes.c_void_p))[0] = 22
            elif pointer.value == 22 and slot == 7:
                assert args == (4,)
                calls.append("antivirus-provider")
            else:
                raise AssertionError((pointer, slot))
            return 0
        return invoke

    monkeypatch.setattr(av_api.sys, "platform", "win32")
    monkeypatch.setattr(av_api.ctypes, "WinDLL", load, raising=False)
    monkeypatch.setattr(av_api, "_av_method", method)
    monkeypatch.setattr(av_api, "_av_read_products", lambda *a: ([{"name": "Fixture"}], ""))
    products, error = av_api.antivirus_products()
    initialized = initialize in (0, 1)
    usable = initialize in (0, 1, -2147417850)
    assert bool(products) is (usable and not fail_create)
    assert bool(error) is (not usable or fail_create)
    assert ("uninitialize" in calls) is initialized
    assert (("release", 11) in calls) is usable
    assert (("release", 22) in calls) is (usable and not fail_create)
    assert all(options == {"winmode": 0x800} for _, options in loads)
    if usable:
        assert ("class", bytes(av_api._av_guid("17072f7b-9abe-4a74-a261-1eb76b55107a")),
                bytes(av_api._av_guid("00000001-0000-0000-c000-000000000046"))) in calls
        assert ("create", bytes(av_api._av_guid("722a338c-6e8e-4e72-ac27-1417fb0c81c2"))) in calls
