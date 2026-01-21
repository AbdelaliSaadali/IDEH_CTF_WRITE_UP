# Write-up: Solving "Frozen Truth"

## Objective
The goal was to extract a hidden flag `IDEH{...}` from a binary executable named `frozen_truth`. The binary was created by a "genius intern" who thought compiling it would protect the secret.

## Initial Analysis
1.  **File Identification**:
    -   Command: `file frozen_truth`
    -   Result: `ELF 64-bit LSB executable`.
    -   Command: `strings frozen_truth`
    -   Result: Strings like `pyi-python-flag` and `PyRun_SimpleStringFlags` confirmed it was a Python script packaged with **PyInstaller**.

2.  **Strategy**:
    -   PyInstaller binaries contain embedded Python bytecode (often compressed with zlib).
    -   The goal became to extract the Python bytecode and decompile/disassemble it.

## Extraction Process
1.  **Scanning for Code**:
    -   A Python script was written to scan the binary for zlib stream headers (`0x789c`, etc.) and decompress them.
    -   The script scanned for keywords like "IDEH" and "Frozen Truth" in the decompressed chunks.
    -   This successfully located a suspicious chunk at offset **76119**.

2.  **Analyzing the Chunk**:
    -   The chunk matched the strings `IDEH{this_is_not_the_flag}` and `SHIFT`.
    -   This chunk was identified as the main `challenge` module's marshalled code object.

## Reverse Engineering the Logic
1.  **Disassembly**:
    -   Using Python's `marshal` and `dis` modules, the code object was loaded and disassembled.
    
2.  **Decoding Logic**:
    -   The disassembly revealed a `main` function and a `decode` function.
    -   **Algorithm**: Simple Caesar cipher (shift subtraction).
    -   **Shift Value**: `SHIFT = 3` (loaded via `LOAD_CONST`).
    -   **Encoded Data**: A list of integers was constructed in the `main` function.

    **Disassembled Logic**:
    ```python
    def decode(data):
        out = bytearray()
        for b in data:
            out.append(b - SHIFT)
        return out.decode('utf-8')
    ```

## Decryption
1.  **Reconstruction**:
    -   The list of integers from the disassembly was:
        `[76, 71, 72, 75, 126, 102, 114, ... 128]`
    -   A script was created to apply the `-3` shift to each integer.

2.  **Result**:
    -   The integers decoded to ASCII characters forming the flag.

## Final Flag
**`IDEH{compiling_wi7h_pyins7all3r_is_no7_s3cur3}`**
