# Adding a reader

`zbtriage/readers.py` is the shared registry for the source CLI, the single-file builder,
platform selection, `--describe` coverage and entry-point test stubs. It holds trusted
built-in readers only; collections and reports cannot install or select arbitrary Python
code.

1. Add `zbtriage/modules/example.py` with a unique `NAME` and
   `run(ctx) -> ModuleResult`. Publish the active result as `ctx.partial` before reading
   records, so cancellation keeps the evidence collected so far.
2. Add one `ReaderSpec` to `READER_SPECS` in `readers.py`: result name, module filename
   without extension, bundle suffix, host platforms, modes, catalogue and any optional
   helper filenames. Descriptor order sets execution and build order. The optional
   `patterns` switch stays explicitly opt-in.
3. List every reported check name and the reader's limitations in its catalogue.
   `contract.CHECK_CATALOGUE` is derived from this metadata; do not keep a second entry
   there. Prefix internal symbols uniquely, because the single-file build shares one
   namespace.
4. Add bounded synthetic fixtures that prove evidence meaning, recovery from malformed
   input, source preservation and source/bundle parity. The registry-wide
   `stub_registered_readers` helper isolates new modules in entry-point tests
   automatically. An end-to-end fixture must opt a real reader back in explicitly and point
   every discovery root at its temporary data.
5. Run the tests and the release check, then update the coverage documentation.

## Modes

`desktop` mode applies the descriptor's host-platform filter. `targeted` mode selects only
readers that handle `ctx.targets` exclusively, and may analyse copied artifacts from another
operating system. `android` and `ios` modes work on the supplied phone collection and never
select host readers. Import failures, invalid result types and runtime failures are reported
as gaps by the shared dispatcher. Per-record recovery is the reader's job.

## Rules for readers

Do not follow executable paths found in artifacts. Read-only analysis must not execute
commands, mount registry hives, resolve links, elevate privileges or download parser
dependencies. Enforce byte, record, traversal and decoding limits before allocating or
decompressing untrusted data. A missing optional artifact is inapplicable; an unreadable
expected or present artifact is a gap. Neither allows claiming that records were parsed
when they were not.

The registry deliberately does not load external plugins. Adding a trusted reader means
reviewing its source, registering it and rebuilding the bundle.
