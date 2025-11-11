# HappyIDA
Make your IDA Happy will also make you Happy!

HappyIDA is an IDAPython plugin that adds a set of convenience hooks and UI helpers to the Hex‑Rays decompiler.
It offers multiple functionalities:

- Function parameter labeling – Swift‑style labels, rename / type edits at the call site.
- Clipboard helpers – copy / paste names, types, and assign types directly from the clipboard.
- Function navigation – double‑click on a vtable name to jump or search for the matching function.
- Try catch block support (SEH) – visual highlights and try...catch clause rebuild support.
- Rust string handling – automatically pretty‑prints Rust strings in decompiled pseudocode.

## Installation

1. IDA Pro 9.0 or later (Hex‑Rays must be enabled).
2. Directly clone this repo to your IDAPython plugins directory (usually ~/.idapro/plugins/)
3. Restart IDA

## Plugin Structure

HappyIDA/
├─ ida_happy/                     # Core package
│   ├─ __init__.py                # Plugin class + actions
│   ├─ miscutils.py               # helpers (logging, tag utils)
│   └─ modules/                   # Individual modules
│       ├─ argument_labeler/
│       │   └─ [label, edit, sync_name, sync_type]
│       ├─ func_navigate.py
│       ├─ rust_string.py
│       └─ seh/
│           └─ [highlight, rebuild]
│
├─ ida-plugin.json                # IDA metadata (plugin name, author)
└─ demo.cpp                       # Example C++ file for demo

### Modules

| Module | Functionality |
|--------|----------------|
| argument_labeler | Adds Swift‑style parameter labels, rename and retype directly at call sites. |
| func_navigate | Double‑click vtable name → jump or search for matching function. |
| rust_string | Detects Rust binaries and pretty‑prints string literals in pseudocode. |
| seh | Highlights structured exception handling blocks and rebuilds SEH try catch clause. |

## Features & Usage

| Feature | How to use |
|---------|------------|
| Copy / Paste Name | happyida:hx_copyname (copy) / happyida:hx_pastename (paste). |
| Copy / Paste Type | happyida:hx_copytype / happyida:hx_pastetype. |
| Edit Parameter | Press Y in a function call when the cursor is on an argument. Choose Rename or Set Type. |
| Assign Clipboard Type | Highlight an expression, press Ctrl+Shift+T → Paste type. |
| Navigate Functions | Double‑click on a vtable entry or member pointer in pseudocode. |
| Rust String Pretty Print | Open a Rust binary – strings automatically colorized in Hex‑Rays. |
| SEH Highlight | SEH blocks are visually highlighted; right‑click → Rebuild SEH. |

## License

Licensed under the GPL license. See LICENSE for details.
