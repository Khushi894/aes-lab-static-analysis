import os
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag

import aes_lab as lab


class AesLabTests(unittest.TestCase):
    def setUp(self):
        self.key = lab.generate_key()

    def test_key_is_256_bit_and_random(self):
        self.assertEqual(len(self.key), 32)
        self.assertNotEqual(self.key, lab.generate_key())

    def test_gcm_roundtrip(self):
        msg = b"hello world" * 10
        self.assertEqual(lab.gcm_decrypt(self.key, lab.gcm_encrypt(self.key, msg)), msg)

    def test_gcm_random_nonce_each_time(self):
        a, b = lab.gcm_encrypt(self.key, b"x" * 32), lab.gcm_encrypt(self.key, b"x" * 32)
        self.assertNotEqual(lab.gcm_parts(a)[0], lab.gcm_parts(b)[0])
        self.assertNotEqual(a, b)

    def test_gcm_detects_every_single_bit_flip_position_class(self):
        blob = lab.gcm_encrypt(self.key, b"authentic data 1234567890")
        for i in range(len(blob)):
            with self.assertRaises(InvalidTag, msg=f"byte {i}"):
                lab.gcm_decrypt(self.key, lab.flip_bit(blob, i))

    def test_gcm_wrong_key_fails(self):
        blob = lab.gcm_encrypt(self.key, b"secret")
        with self.assertRaises(InvalidTag):
            lab.gcm_decrypt(lab.generate_key(), blob)

    def test_ecb_leaks_repetition_gcm_does_not(self):
        data = b"A" * 16 * 20
        _, unique_ecb, top_ecb = lab.block_stats(lab.ecb_encrypt(self.key, data)[:len(data)])
        _, unique_gcm, top_gcm = lab.block_stats(lab.gcm_parts(lab.gcm_encrypt(self.key, data))[1])
        self.assertEqual((unique_ecb, top_ecb), (1, 20))
        self.assertEqual((unique_gcm, top_gcm), (20, 1))

    def test_ecb_has_no_integrity(self):
        ct = lab.ecb_encrypt(self.key, b"B" * 48)
        lab.ecb_decrypt_nopad(self.key, lab.flip_bit(ct, 5))  # no exception raised

    def test_missing_key_env_exits(self):
        old = os.environ.pop(lab.KEY_ENV, None)
        try:
            with self.assertRaises(SystemExit):
                lab.load_key()
        finally:
            if old is not None:
                os.environ[lab.KEY_ENV] = old

    def test_source_contains_no_hardcoded_key(self):
        src = Path(lab.__file__).read_text(encoding="utf-8")
        self.assertNotIn(lab.encode_key(self.key), src)


if __name__ == "__main__":
    unittest.main()
