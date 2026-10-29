"""Read Windows Security Center's registered antivirus product state.

Uses the system WSC class factory directly: no vendor programs, per-user COM
activation, registry writes, remediation actions or protection changes.
"""
import ctypes
import sys
import uuid


def _av_guid(value):
    return (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(value).bytes_le)


def _av_method(pointer, slot, *arguments):
    if not pointer:
        raise OSError("Windows Security Center returned an empty interface")
    table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    factory = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
    return factory(ctypes.c_int32, ctypes.c_void_p, *arguments)(table[slot])


def _av_check(code):
    if code < 0:
        raise OSError("Windows Security Center request failed (0x{:08x})".format(code & 0xffffffff))


def _av_release(pointer):
    if pointer:
        _av_method(pointer, 2)(pointer)


def _av_read_products(product_list, automation):
    count = ctypes.c_int32()
    _av_check(_av_method(product_list, 8, ctypes.POINTER(ctypes.c_int32))(product_list, ctypes.byref(count)))
    if not 0 <= count.value <= 128:
        raise OSError("Windows Security Center product count exceeds the supported limit")
    products, errors = [], []
    for index in range(count.value):
        product, name = ctypes.c_void_p(), ctypes.c_void_p()
        try:
            _av_check(_av_method(product_list, 9, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p))(
                product_list, index, ctypes.byref(product)))
            _av_check(_av_method(product, 7, ctypes.POINTER(ctypes.c_void_p))(product, ctypes.byref(name)))
            length = automation.SysStringLen(name)
            if not name or not 0 < length <= 4096:
                raise OSError("Windows Security Center product name is unavailable or oversized")
            display = ctypes.wstring_at(name, length)
            state, signature = ctypes.c_int32(), ctypes.c_int32()
            _av_check(_av_method(product, 8, ctypes.POINTER(ctypes.c_int32))(product, ctypes.byref(state)))
            _av_check(_av_method(product, 9, ctypes.POINTER(ctypes.c_int32))(product, ctypes.byref(signature)))
            if state.value not in (0, 1, 2, 3) or signature.value not in (0, 1):
                raise OSError("Windows Security Center returned an unsupported product state")
            row = {"name": display, "state": state.value, "signature_status": signature.value}
            if row not in products:
                products.append(row)
        except OSError as exc:
            errors.append(str(exc))
        finally:
            if name:
                automation.SysFreeString(name)
            _av_release(product)
    return products, "; ".join(dict.fromkeys(errors))


def antivirus_products():
    """(registered product records, uncertainty); registration is not a security guarantee."""
    if sys.platform != "win32":
        return [], "Windows Security Center is unavailable on this platform"
    product_list, factory = ctypes.c_void_p(), ctypes.c_void_p()
    initialized = False
    ole = None
    try:
        # Restrict every load to the Windows system directory. Obtain the class
        # factory from that DLL, avoiding user-controlled COM registrations.
        ole = ctypes.WinDLL("ole32.dll", winmode=0x800)
        automation = ctypes.WinDLL("oleaut32.dll", winmode=0x800)
        wsc = ctypes.WinDLL("wscapi.dll", winmode=0x800)
        ole.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        ole.CoInitializeEx.restype = ctypes.c_int32
        ole.CoUninitialize.argtypes = []
        ole.CoUninitialize.restype = None
        automation.SysStringLen.argtypes = [ctypes.c_void_p]
        automation.SysStringLen.restype = ctypes.c_uint32
        automation.SysFreeString.argtypes = [ctypes.c_void_p]
        automation.SysFreeString.restype = None
        wsc.DllGetClassObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        wsc.DllGetClassObject.restype = ctypes.c_int32
        code = ole.CoInitializeEx(None, 2)
        if code >= 0:
            initialized = True
        elif (code & 0xffffffff) != 0x80010106:  # existing apartment is usable
            _av_check(code)
        clsid = _av_guid("17072f7b-9abe-4a74-a261-1eb76b55107a")
        factory_id = _av_guid("00000001-0000-0000-c000-000000000046")
        interface_id = _av_guid("722a338c-6e8e-4e72-ac27-1417fb0c81c2")
        _av_check(wsc.DllGetClassObject(clsid, factory_id, ctypes.byref(factory)))
        _av_check(_av_method(factory, 3, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))(
            factory, None, interface_id, ctypes.byref(product_list)))
        _av_check(_av_method(product_list, 7, ctypes.c_uint32)(product_list, 4))  # antivirus provider
        return _av_read_products(product_list, automation)
    except (OSError, AttributeError, ValueError) as exc:
        return [], "Antivirus status could not be read: " + str(exc)
    finally:
        _av_release(product_list)
        _av_release(factory)
        if initialized and ole is not None:
            ole.CoUninitialize()
