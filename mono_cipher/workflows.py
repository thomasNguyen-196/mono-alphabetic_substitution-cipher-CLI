"""
Application workflows that orchestrate the UI and monoalphabetic cipher logic.
"""

import sys
from typing import Optional
from . import ui
from . import cipher


def _strip_saved_header(text: str) -> str:
    """
    Removes the single-line header we add when saving (e.g., 'Plaintext | Key: ...')
    so reusing a saved file won't accidentally re-process the header.
    """
    lines = text.splitlines()
    if lines and "key:" in lines[0].lower():
        lines = lines[1:]
        while lines and not lines[0].strip():
            lines = lines[1:]
    return "\n".join(lines)


def _read_text_input(label: str) -> str:
    """
    Reads potentially large text either from stdin (if piped), a file, or direct input.
    """
    if not sys.stdin.isatty():
        data = sys.stdin.read()
        return _strip_saved_header(data.rstrip("\n"))

    print(ui.FG["yellow"] + "For large text, you can read from file by pressing 'f'." + ui.RESET)
    mode = ui.prompt("Enter directly [Enter] or type 'f' to load from file: ").strip().lower()
    if mode == "f":
        while True:
            path = ui.prompt("Path to file: ").strip()
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return _strip_saved_header(f.read())
            except Exception as e:
                print(ui.FG["red"] + f"Could not read file: {e}" + ui.RESET)
                retry = ui.prompt("Try again? (y/n): ").strip().lower()
                if retry != "y":
                    return ""
    return ui.prompt(f"{label}: ")


def _read_key() -> str:
    """
    Prompts for a 26-letter substitution alphabet.
    Non-letters are ignored; validation ensures length 26 with no duplicates.
    """
    while True:
        key = ui.prompt("Substitution key (26 letters, e.g., QWERTY...): ").strip()
        try:
            cipher.validate_key(key)
            return key
        except ValueError as e:
            print(ui.FG["red"] + f"Invalid key: {e}" + ui.RESET)


def encrypt_flow():
    """Workflow for encrypting a message."""
    ui.clear()
    ui.banner()
    ui.boxed("ENCRYPT", "Enter plaintext and a 26-letter substitution key.")
    plaintext = _read_text_input("Plaintext")
    key = _read_key()
    ciphertext = cipher.encrypt(plaintext, key)
    ui.boxed("RESULT", ciphertext)
    post_output_actions(ciphertext, key=key, label="Ciphertext")


def decrypt_flow():
    """Workflow for decrypting a message."""
    ui.clear()
    ui.banner()
    ui.boxed("DECRYPT", "Enter ciphertext and the same 26-letter key.")
    ciphertext = _read_text_input("Ciphertext")
    key = _read_key()
    plaintext = cipher.decrypt(ciphertext, key)
    ui.boxed("RESULT", plaintext)
    post_output_actions(plaintext, key=key, label="Plaintext")


def post_output_actions(text: str, key: Optional[str] = None, label: str = ""):
    """
    Handles actions after a result is generated (copy, save, etc.).
    When saving to file, the key (if provided) is written alongside the output.
    """
    print()
    print(ui.FG["cyan"] + "[1] Copy to clipboard   [2] Save to file   [Enter] Back" + ui.RESET)
    cmd = ui.prompt("Select: ").strip()
    if cmd == "1":
        if ui.pyperclip:
            try:
                ui.pyperclip.copy(text)
                print(ui.FG["green"] + "Copied to clipboard." + ui.RESET)
            except Exception as e:
                print(ui.FG["red"] + f"Copy failed: {e}" + ui.RESET)
        else:
            print(ui.FG["yellow"] + "pyperclip not installed; cannot copy." + ui.RESET)
    elif cmd == "2":
        fname = ui.prompt("Save file name (default output.txt): ").strip() or "output.txt"
        content = text
        if key is not None:
            header_parts = []
            if label:
                header_parts.append(label)
            header_parts.append(f"Key: {key}")
            header = " | ".join(header_parts)
            content = f"{header}\n\n{text}"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(content)
            print(ui.FG["green"] + f"Saved to {fname}" + ui.RESET)
        except Exception as e:
            print(ui.FG["red"] + f"Save failed: {e}" + ui.RESET)
    else:
        return
    ui.prompt("Press Enter to continue...")


def save_or_copy_flow(text: str):
    """A mini-flow for saving or copying a large block of text."""
    print(ui.FG["cyan"] + "Choose: (1) copy, (2) save file, (3) print, (q) cancel" + ui.RESET)
    cmd = ui.prompt("> ").strip().lower()
    if cmd == "1":
        if ui.pyperclip:
            ui.pyperclip.copy(text)
            print(ui.FG["green"] + "Copied all results." + ui.RESET)
        else:
            print(ui.FG["yellow"] + "pyperclip not installed." + ui.RESET)
    elif cmd == "2":
        fname = ui.prompt("File name: ").strip() or "results.txt"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(text)
        print(ui.FG["green"] + f"Saved to {fname}" + ui.RESET)
    elif cmd == "3":
        print("\n" + text + "\n")
    else:
        print("Cancelled.")


def show_help():
    """Displays the help screen."""
    ui.clear()
    ui.banner()
    help_text = (
        "Usage:\n"
        "- Encrypt/decrypt with a 26-letter substitution key (duplicates not allowed).\n"
        "- Long text can be provided via file (choose 'f') or piped stdin: cat file.txt | mono\n"
        "- You can copy or save results after each action.\n"
        "- Optional visuals: pip install pyfiglet colorama pyperclip\n"
    )
    ui.boxed("HELP", help_text)
    ui.prompt("Press Enter to return to menu...")
