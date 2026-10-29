"""Scan modules. Each module file defines:

    NAME: str
    def run(ctx: zbtriage.context.ScanContext) -> zbtriage.result.ModuleResult

and records every sub-check with result.ModuleResult.ran() / .could_not_run()
so that CLEAN is never reported for something that did not actually execute (D3).
"""
