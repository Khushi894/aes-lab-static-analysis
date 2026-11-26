#!/usr/bin/env python3
"""
AES encryption lab: AES-ECB (insecure) vs AES-GCM (authenticated encryption).

Library : pyca/cryptography (OpenSSL backend)
Key     : 256-bit, generated with the OS CSPRNG, supplied ONLY through the
          AES_KEY environment variable (URL-safe base64). Never stored in code
          or in the repository.

Sub-commands
------------
  genkey                      print a fresh random 256-bit key (base64)
  encrypt -i IN -o OUT        AES-256-GCM file encryption (random nonce per call)
  decrypt -i IN -o OUT        AES-256-GCM file decryption + tag verification
  demo    [-d OUTDIR]         ECB vs GCM on a bitmap and on repeating text
  tamper  [-d OUTDIR]         flip bits in ciphertext and show GCM rejecting it

GCM file format:  MAGIC(4) | NONCE(12) | CIPHERTEXT(n) | TAG(16)
The MAGIC header is bound to the ciphertext as Associated Data (AAD), so a
modified header is also detected.
"""
import argparse
import base64
import binascii
import os
import secrets
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_ENV = "AES_KEY"
KEY_BYTES = 32      # AES-256
NONCE_BYTES = 12    # 96-bit nonce, the recommended size for GCM
TAG_BYTES = 16      # 128-bit authentication tag
BLOCK_BYTES = 16
MAGIC = b"AGC1"     # file-format marker, authenticated as AAD


# --------------------------------------------------------------------------
# Key management
# --------------------------------------------------------------------------
def generate_key() -> bytes:
    """Return 32 bytes from the operating system's CSPRNG (os.urandom)."""
    return secrets.token_bytes(KEY_BYTES)


def encode_key(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode("ascii")


def load_key() -> bytes:
    """Read the key from the AES_KEY environment variable and validate it."""
    value = os.environ.get(KEY_ENV)
    if not value:
        sys.exit(
            f"error: environment variable {KEY_ENV} is not set.\n"
            f"  bash:        export {KEY_ENV}=$(python aes_lab.py genkey)\n"
            f"  PowerShell:  $env:{KEY_ENV} = (python aes_lab.py genkey)"
        )
    try:
        key = base64.urlsafe_b64decode(value.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError):
        sys.exit(f"error: {KEY_ENV} is not valid URL-safe base64.")
    if len(key) != KEY_BYTES:
        sys.exit(f"error: {KEY_ENV} must decode to {KEY_BYTES} bytes (got {len(key)}).")
    return key


# --------------------------------------------------------------------------
# AES-ECB  (INSECURE - included only to demonstrate why it must not be used)
# --------------------------------------------------------------------------
def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(padded) + enc.finalize()


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def ecb_decrypt_nopad(key: bytes, ciphertext: bytes) -> bytes:
    """Raw ECB decryption without unpadding (used to show silent corruption)."""
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(ciphertext) + dec.finalize()


# --------------------------------------------------------------------------
# AES-GCM  (authenticated encryption)
# --------------------------------------------------------------------------
def gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = MAGIC) -> bytes:
    """Return MAGIC | nonce | ciphertext | tag. A fresh random nonce is used
    for every call; reusing a (key, nonce) pair under GCM is catastrophic."""
    nonce = secrets.token_bytes(NONCE_BYTES)
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return MAGIC + nonce + ct_and_tag


def gcm_decrypt(key: bytes, blob: bytes, aad: bytes = MAGIC) -> bytes:
    """Verify the tag and decrypt. Raises InvalidTag if anything was altered."""
    if len(blob) < len(MAGIC) + NONCE_BYTES + TAG_BYTES or blob[:4] != MAGIC:
        raise InvalidTag("malformed or truncated GCM container")
    nonce = blob[4:4 + NONCE_BYTES]
    ct_and_tag = blob[4 + NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ct_and_tag, aad)


def gcm_parts(blob: bytes):
    """Split a container into (nonce, ciphertext, tag) for display."""
    nonce = blob[4:4 + NONCE_BYTES]
    return nonce, blob[4 + NONCE_BYTES:-TAG_BYTES], blob[-TAG_BYTES:]


# --------------------------------------------------------------------------
# Analysis helpers
# --------------------------------------------------------------------------
def block_stats(data: bytes):
    """(total 16-byte blocks, unique blocks, most common block repeat count)."""
    blocks = [data[i:i + BLOCK_BYTES] for i in range(0, len(data) - len(data) % BLOCK_BYTES, BLOCK_BYTES)]
    counts = {}
    for b in blocks:
        counts[b] = counts.get(b, 0) + 1
    return len(blocks), len(counts), max(counts.values()) if counts else 0


def flip_bit(data: bytes, index: int, bit: int = 0) -> bytes:
    buf = bytearray(data)
    buf[index] ^= 1 << bit
    return bytes(buf)


# --------------------------------------------------------------------------
# Test image (24-bit BMP with large flat regions -> strong visual structure)
# --------------------------------------------------------------------------
def make_test_bitmap(path: Path, size: int = 256) -> None:
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", (size, size), (255, 255, 255))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, size - 1, size // 4], fill=(20, 60, 140))                 # banner
    d.ellipse([size * 0.14, size * 0.32, size * 0.62, size * 0.80], fill=(200, 30, 40))
    d.polygon([(size * 0.55, size * 0.35), (size * 0.92, size * 0.35),
               (size * 0.92, size * 0.85), (size * 0.72, size * 0.97)], fill=(30, 140, 70))
    d.rectangle([size * 0.10, size * 0.88, size * 0.50, size * 0.95], fill=(0, 0, 0))
    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", size // 8)
    except OSError:
        font = ImageFont.load_default(size // 8)
    d.text((size * 0.06, size * 0.06), "AES LAB", fill=(255, 255, 255), font=font)
    img.save(path, format="BMP")


def split_bmp(data: bytes):
    """Return (header, pixel_bytes) of a BMP using the pixel-array offset."""
    offset = struct.unpack_from("<I", data, 10)[0]
    return data[:offset], data[offset:]


def side_by_side(images, labels, out_path: Path, scale: int = 1) -> None:
    from PIL import Image, ImageDraw, ImageFont

    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", 16)
    except OSError:
        font = ImageFont.load_default(16)
    w, h = images[0].size
    w, h = w * scale, h * scale
    pad, bar = 16, 34
    canvas = Image.new("RGB", (len(images) * (w + pad) + pad, h + bar + pad), (245, 245, 245))
    d = ImageDraw.Draw(canvas)
    for i, (im, label) in enumerate(zip(images, labels)):
        x = pad + i * (w + pad)
        canvas.paste(im.resize((w, h), Image.NEAREST), (x, bar))
        d.text((x, 8), label, fill=(0, 0, 0), font=font)
    canvas.save(out_path)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_genkey(_args) -> None:
    print(encode_key(generate_key()))


def cmd_encrypt(args) -> None:
    key = load_key()
    plaintext = Path(args.input).read_bytes()
    Path(args.output).write_bytes(gcm_encrypt(key, plaintext))
    print(f"encrypted {args.input} -> {args.output} (AES-256-GCM, random 96-bit nonce)")


def cmd_decrypt(args) -> None:
    key = load_key()
    blob = Path(args.input).read_bytes()
    try:
        plaintext = gcm_decrypt(key, blob)
    except InvalidTag:
        print("AUTHENTICATION FAILED: ciphertext/tag/nonce was modified or key is wrong. "
              "No plaintext released.", file=sys.stderr)
        sys.exit(2)
    Path(args.output).write_bytes(plaintext)
    print(f"decrypted {args.input} -> {args.output} (authentication tag verified)")


def cmd_demo(args) -> None:
    from PIL import Image

    key = load_key()
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)
    print("Key loaded from environment variable AES_KEY (value never printed).\n")

    # ---- (2) random IV/nonce per encryption ------------------------------
    print("== Random nonce per encryption ==")
    msg = b"same plaintext, encrypted twice"
    c1, c2 = gcm_encrypt(key, msg), gcm_encrypt(key, msg)
    print(f"nonce #1 : {gcm_parts(c1)[0].hex()}")
    print(f"nonce #2 : {gcm_parts(c2)[0].hex()}")
    print(f"ciphertext #1 : {gcm_parts(c1)[1].hex()}")
    print(f"ciphertext #2 : {gcm_parts(c2)[1].hex()}")
    print(f"identical ciphertexts? {gcm_parts(c1)[1] == gcm_parts(c2)[1]}")
    print(f"ECB, same plaintext twice -> identical? {ecb_encrypt(key, msg) == ecb_encrypt(key, msg)}\n")

    # ---- (3a) bitmap ------------------------------------------------------
    print("== Bitmap: ECB vs GCM ==")
    plain_bmp_path = out / "plain.bmp"
    make_test_bitmap(plain_bmp_path)
    bmp = plain_bmp_path.read_bytes()
    header, pixels = split_bmp(bmp)

    ecb_ct = ecb_encrypt(key, pixels)
    gcm_blob = gcm_encrypt(key, pixels)
    _, gcm_ct, _ = gcm_parts(gcm_blob)

    # Re-attach the (public) BMP header so the ciphertext can be viewed as an image.
    (out / "ecb.bmp").write_bytes(header + ecb_ct[:len(pixels)])
    (out / "gcm.bmp").write_bytes(header + gcm_ct[:len(pixels)])

    for name, data in (("plaintext pixels", pixels), ("AES-ECB ciphertext", ecb_ct),
                       ("AES-GCM ciphertext", gcm_ct)):
        total, unique, top = block_stats(data)
        print(f"{name:20s}: {total} blocks, {unique} unique, most-repeated block x{top}")

    assert ecb_decrypt(key, ecb_ct) == pixels
    assert gcm_decrypt(key, gcm_blob) == pixels
    print("round-trip decryption verified for both modes")

    imgs = [Image.open(out / n).convert("RGB") for n in ("plain.bmp", "ecb.bmp", "gcm.bmp")]
    side_by_side(imgs, ["Plaintext", "AES-256-ECB", "AES-256-GCM"], out / "comparison.png", scale=2)
    print(f"saved {out/'comparison.png'}\n")

    # ---- (3b) repeating text ---------------------------------------------
    print("== Text with repeating content: ECB vs GCM (16-byte blocks) ==")
    text = (b"ATTACK AT DAWN!!" * 3 + b"RETREAT AT DUSK!" + b"ATTACK AT DAWN!!" * 2)
    ecb_t = ecb_encrypt(key, text)
    gcm_t = gcm_parts(gcm_encrypt(key, text))[1]
    lines = [f"{'blk':>3}  {'plaintext':16}  {'ECB ciphertext block':32}  GCM ciphertext block"]
    for i in range(0, len(text), BLOCK_BYTES):
        lines.append(f"{i // 16:>3}  {text[i:i+16].decode():16}  {ecb_t[i:i+16].hex():32}  {gcm_t[i:i+16].hex()}")
    table = "\n".join(lines)
    print(table)
    (out / "text_blocks.txt").write_text(table + "\n")
    print(f"ECB: {block_stats(ecb_t[:len(text)])[1]} unique of {len(text)//16} blocks;"
          f" GCM: {block_stats(gcm_t)[1]} unique of {len(text)//16} blocks")


def cmd_tamper(args) -> None:
    key = load_key()
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)

    plaintext = b"Transfer 100 to Alice. Account: 4417-0021. Authorised by: Bob."
    blob = gcm_encrypt(key, plaintext)
    nonce, ct, tag = gcm_parts(blob)
    print(f"plaintext          : {plaintext.decode()}")
    print(f"container length   : {len(blob)} bytes (4 magic + 12 nonce + {len(ct)} ct + 16 tag)\n")

    print("== Baseline: untouched ciphertext ==")
    print("decrypt ->", gcm_decrypt(key, blob).decode(), "\n")

    ct_start = 4 + NONCE_BYTES
    cases = [
        ("flip 1 bit in ciphertext body", flip_bit(blob, ct_start + 10)),
        ("flip 1 bit in authentication tag", flip_bit(blob, len(blob) - 1)),
        ("flip 1 bit in nonce", flip_bit(blob, 4 + 3)),
        ("flip 1 bit in header (AAD)", flip_bit(blob, 0)),
        ("truncate last byte", blob[:-1]),
        ("append one byte", blob + b"\x00"),
    ]
    print("== AES-GCM tamper tests ==")
    all_rejected = True
    for label, bad in cases:
        try:
            gcm_decrypt(key, bad)
            result = "ACCEPTED  <-- authentication failure not detected!"
            all_rejected = False
        except InvalidTag:
            result = "REJECTED  (InvalidTag - no plaintext released)"
        print(f"{label:34s}: {result}")
    print(f"\nall tampered ciphertexts rejected: {all_rejected}\n")

    # Wrong key must fail as well
    try:
        gcm_decrypt(generate_key(), blob)
        print("wrong key: ACCEPTED (unexpected)")
    except InvalidTag:
        print("wrong key                         : REJECTED  (InvalidTag)\n")

    # File-level tamper, same as an attacker editing the file on disk
    enc, bad_enc = out / "message.enc", out / "message_tampered.enc"
    enc.write_bytes(blob)
    bad_enc.write_bytes(flip_bit(blob, ct_start + 10))
    print(f"wrote {enc} and {bad_enc} (one bit differs)\n")

    # Contrast with ECB
    print("== Contrast: AES-ECB has no integrity protection ==")
    ecb_ct = ecb_encrypt(key, plaintext)
    bad = flip_bit(ecb_ct, 10)
    recovered = ecb_decrypt_nopad(key, bad)
    print("original  :", plaintext)
    print("after flip:", recovered[:len(plaintext)])
    print("-> ECB decrypts without any error; one block silently becomes garbage.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("genkey", help="print a new random 256-bit key").set_defaults(fn=cmd_genkey)
    for name, fn in (("encrypt", cmd_encrypt), ("decrypt", cmd_decrypt)):
        sp = sub.add_parser(name, help=f"{name} a file with AES-256-GCM")
        sp.add_argument("-i", "--input", required=True)
        sp.add_argument("-o", "--output", required=True)
        sp.set_defaults(fn=fn)
    for name, fn in (("demo", cmd_demo), ("tamper", cmd_tamper)):
        sp = sub.add_parser(name)
        sp.add_argument("-d", "--outdir", default="evidence")
        sp.set_defaults(fn=fn)
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
