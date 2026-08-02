# Kaitai spec for the binary `.mpkinfo` VFS index.
#
# See docs/mpkinfo-index.md for the full format description, including the
# ASCII `HEXB_` variant that this spec does NOT cover: some files carrying an
# .mpkinfo extension are integrity-metadata wrappers, not binary indexes.
# Sniff the leading bytes for `HEX_`/`HEXB_` before applying this spec.
#
# This spec is kept as documentation. The runtime parser is
# src/messiah/vfs/mpkinfo.py, which also handles the HEXB_ variant.
meta:
  id: file_fmt
  endian: le

seq:
  - id: magic
    type: u4
    valid:
      eq: 3
  - id: file_nums
    type: u4
  - id: patterns
    type: pattern
    repeat: expr
    repeat-expr: file_nums
  - id: p4
    type: u8
  - id: p5
    type: u8

types:
  pattern:
    seq:
      - id: s0
        type: u4
      - id: s1
        type: u4
      - id: offset
        type: u4
      - id: size
        type: u4
      # Bit-packed. Historically mis-named `patch_id` and decoded as `// 2`,
      # which silently discarded the type flag.
      - id: packed
        type: u4
    instances:
      file_id:
        value: (s1 << 32) | s0
      pack_id:
        value: packed >> 1
      typeflag:
        value: packed & 1
