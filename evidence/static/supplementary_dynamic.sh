#!/usr/bin/env bash
# Supplementary dynamic checks for static findings that Q1 did not exercise.
set -u
cd "$(dirname "$0")/../.."
W=$(mktemp -d); export AES_KEY=$(python3 aes_lab.py genkey); umask 022
echo "hello secret" > "$W/p.txt"
python3 aes_lab.py encrypt -i "$W/p.txt" -o "$W/c.enc" >/dev/null
echo "== T1: permissions of decrypted plaintext (umask 022) =="
python3 aes_lab.py decrypt -i "$W/c.enc" -o "$W/p.dec" >/dev/null; stat -c '%a %n' "$W/p.dec" "$W/c.enc"
echo "== T2: output path is a pre-planted symlink to a victim file =="
echo "VICTIM ORIGINAL" > "$W/victim.txt"; ln -s "$W/victim.txt" "$W/out.txt"
python3 aes_lab.py decrypt -i "$W/c.enc" -o "$W/out.txt" >/dev/null
echo "victim.txt now contains: $(cat "$W/victim.txt")"
echo "== T2b: same symlink trick against the ENCRYPT output path =="
echo "VICTIM2 ORIGINAL" > "$W/victim2.txt"; ln -s "$W/victim2.txt" "$W/out2.enc"
python3 aes_lab.py encrypt -i "$W/p.txt" -o "$W/out2.enc" >/dev/null
echo "victim2.txt now starts with magic bytes: $(head -c4 "$W/victim2.txt")"
echo "== T3: output path with ../ components (CLI operator privilege) =="
mkdir -p "$W/sub"; python3 aes_lab.py decrypt -i "$W/c.enc" -o "$W/sub/../escaped.txt" >/dev/null; ls "$W/escaped.txt"
echo "== T4: python -O (asserts stripped) still runs demo =="
python3 -O aes_lab.py demo -d "$W/ev" | tail -2
rm -rf "$W"
