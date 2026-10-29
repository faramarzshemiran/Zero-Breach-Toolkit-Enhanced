"""Registry-wide isolation for entry-point fixtures; new readers default to stubs."""
import importlib
from unittest.mock import patch

from zbtriage.readers import READER_SPECS
from zbtriage.result import ModuleResult


def stub_registered_readers(stack, bundle=None, keep=()):
    specs = bundle.READER_SPECS if bundle is not None else READER_SPECS
    result_type = bundle.ModuleResult if bundle is not None else ModuleResult
    patched = []
    for spec in specs:
        if spec.name in keep:
            continue
        def empty(ctx, name=spec.name):
            result = result_type(name)
            result.ran("fixture")
            return result
        if bundle is None:
            module = importlib.import_module("zbtriage.modules." + spec.module)
            stack.enter_context(patch.object(module, "run", empty))
        else:
            stack.enter_context(patch.object(bundle, "run_" + spec.suffix, empty))
        patched.append(spec.name)
    return patched
