# Synthetic RI-subkey-list regression fixtures

These fixed files preserve the exact output of `_hive()` from
`tests/test_ri_cycle.py` at source revision
`14c55880bd91b9fa0da09e043883ecf08c04196e`. The helper was run once for each
case below. No generator or file mutation runs during the tests. Each file
contains only synthetic headers and zero padding; none contains data collected
from a Windows installation.

| File | Bytes | RI target(s) | Behavior without the fix | SHA-256 |
| --- | ---: | --- | --- | --- |
| `ri-self-reference.hive` | 8192 | `ri` → itself | `RecursionError` | `6f14e63654b15bf5ce194133a00a957ba3286fb744f2bf8add5dcfa952692edf` |
| `ri-mutual-reference.hive` | 8192 | `ri` → second `ri` → first `ri` | `RecursionError` | `51ea82b27fc22cbcb4883f4914613e9ff6040f3c58a79de51f3a7ba9cfdd1861` |
| `ri-points-to-nk.hive` | 8192 | `ri` → root `nk` cell | `AttributeError` | `f1d9a7dd2b5b8f8b3d7e1ded7fe55ee24ded42ce05e97078d63468e01fda6f6e` |

With the fix, enumerating subkeys on all three raises `ParseException`.

## Layout

Offsets below are absolute file offsets; stored cell pointers are relative to
the HBIN base at `0x1000`. Integers are little-endian. All three files share one
layout and differ only in the RI entries.

- REGF header at `0x0`. The root cell pointer at `0x24` is `0x20`; the declared
  hive-bin size at `0x28` is `0x1000`. The REGF checksum is left zero.
- A single HBIN begins at `0x1000`; its size field at `0x1008` is `0x1000`.
- The root NK cell size field is at `0x1020` and `nk` begins at `0x1024`. It has
  root flags `0x2c`, a subkey count of 1, and a subkey-list pointer (`nk+0x1c`,
  at `0x103c`) of `0x80`, which selects the RI cell.
- The first RI cell size field is at `0x1080`, `ri` begins at `0x1084`, the entry
  count `1` is at `0x1086`, and the first entry target offset is at `0x1088`.
  - `ri-self-reference.hive`: the target at `0x1088` is `0x80`.
  - `ri-mutual-reference.hive`: the target at `0x1088` is `0x90`; a second RI cell
    at `0x1090` (`ri` at `0x1094`) has its target at `0x1098` set to `0x80`.
  - `ri-points-to-nk.hive`: the target at `0x1088` is `0x20`, the root NK cell.
- The remainder of the HBIN after the RI cell(s) is a single free cell.

## Limitations

These are deliberately malformed regression inputs, not valid Windows hives. An
RI list that points back to itself, or at a non-list cell, cannot occur in a
well-formed hive, so no real-system capture can reproduce these cases. The files
are minimal: one HBIN of `0x1000` bytes, a zero REGF checksum, no timestamps and
no real subkeys. Other tools may reject them before reaching RI traversal;
cross-tool acceptance has not been tested.

## Run and inspect

From the repository root, with project dependencies installed:

```sh
sha256sum testing/reg_samples/ri_cycle/*.hive
PYTHONPATH=. python -m unittest discover -s tests -p 'test_ri_cycle.py' -v
```

On macOS, use `shasum -a 256` instead of `sha256sum` if needed. The tests check
these hashes before parsing, so any change to the bytes fails loudly. The fixed
parser should pass all three tests; on an unpatched parser the two self/mutual
cases raise `RecursionError` and the non-list case raises `AttributeError`.
