# Synthetic aliased large-data fixtures

These fixed files preserve the exact output of `build_aliased_hive()` from
`tests/test_large_data_alias.py` at source revision
`f84b1731e5c31d282a71235c761e4816327d2cc4`. The helper was run once with
`0x200000` and `0x4000`, respectively. No generator or file mutation runs during
the tests. Both files contain only synthetic headers, zero padding and `A` bytes;
neither contains data collected from a Windows installation.

| File | Bytes | Declared value length | SHA-256 |
| --- | ---: | ---: | --- |
| `oversized.hive` | 552924 | 2097152 (2 MiB) | `3e1b933aa72839ad9844d5dc321e8a0074fd2c95a277ab564f024a87bde1189c` |
| `small-control.hive` | 552924 | 16384 (16 KiB) | `6db19df93a079bea639c65b27703bc0445728eb9a944b0ca755a64422e59e2cc` |

## Layout and limitations

Offsets below are absolute file offsets; stored cell pointers are relative to
the HBIN base at `0x1000`. Integers are little-endian.

- The root NK cell is at `0x1020`, the value list at `0x1140`, and the single
  unnamed RegBin VK cell at `0x1180`.
- The VK length is at `0x1188`; the data pointer at `0x118c` references the DB
  cell at `0x1200`. The DB points to an indirect cell at `0x1240`.
- The offset table begins at `0x1244`. It contains 129 entries in the oversized
  file and two in the control, all pointing to the same data cell at `0x82000`.
- The payload is `0x3fd8` bytes of `A`, starting at `0x82004`. The control returns
  exactly `b'A' * 0x4000` after reusing the start of this cell for its second segment.

These are deliberately malformed regression inputs, not valid Windows hives.
The original generator leaves the REGF checksum and DB segment count zero,
declares only `0x1000` bytes of hive bins, and uses cell sizes that do not describe
all stored payload/table bytes. Those bytes are preserved, including the padding,
so that results can be compared with the original regression. Other tools may
reject them before reaching large-data reassembly. Cross-tool acceptance has not
been tested. The existing ProductPolicy test remains the real-hive control.

## Run and inspect

From the repository root, with project dependencies installed:

```sh
sha256sum testing/reg_samples/large_data_alias/*.hive
PYTHONPATH=. python -m unittest discover -s tests -p 'test_large_data*.py' -v
```

On macOS, use `shasum -a 256` instead of `sha256sum` if needed. The tests check
these hashes before parsing, so any change to the bytes fails loudly. The fixed parser
should pass all three tests. Without the length guard, the oversized rejection
test should fail and both controls should pass. The oversized input declares
only 2 MiB to bound this regression; it is not the earlier roughly 2 GiB PoC.
