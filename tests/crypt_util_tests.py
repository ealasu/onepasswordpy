import mock
import testify as T

from onepassword import crypt_util


class HexizeTestCase(T.TestCase):
    VECTORS = (
        ('', ''),
        ('\x00', '00'),
        ('abcd', '61626364'),
        ('\x00,123', '002C313233'),
    )
    def test_hexize_simple(self):
        for unhexed, hexed in self.VECTORS:
            T.assert_equal(crypt_util.hexize(unhexed), hexed)

    def test_unhexize_simple(self):
        for unhexed, hexed in self.VECTORS:
            T.assert_equal(crypt_util.unhexize(hexed), unhexed)


class PBKDF1TestCase(T.TestCase):
    # test vectors generated with
    # openssl enc -aes-128-cbc -p -k <PASSWORD> -a -nosalt -p < /dev/null
    VECTORS = (
        ('password', '', '5F4DCC3B5AA765D61D8327DEB882CF99', '2B95990A9151374ABD8FF8C5A7A0FE08'),
        ('', '', 'D41D8CD98F00B204E9800998ECF8427E', '59ADB24EF3CDBE0297F05B395827453F'),
        ('', 'E3936A9A8ACFE9BE', 'E9FAB75961E5DE62D6982C3F569114A5', '652D875150F652F75154666E1FD0E8AC'),
        ('012345678910111231415161717', 'F7560045C70A96DB', '2E14B2EC7E2F8CDC18F15BB773CCD6F2', '5C8AADA268F9B86F960DF0464AE5E981'),
    )

    def test_vectors(self):
        for password, hex_salt, expected_key, expected_iv in self.VECTORS:
            salt = crypt_util.unhexize(hex_salt)
            derived_key, derived_iv = crypt_util.pbkdf1(password, salt, key_size=16, rounds=2)
            hex_derived_key = crypt_util.hexize(derived_key)
            hex_derived_iv = crypt_util.hexize(derived_iv)
            T.assert_equal(hex_derived_key, expected_key)
            T.assert_equal(hex_derived_iv, expected_iv)

    def test_count(self):
        # can't use vectors as easily here because openssl never passes
        # count != 1
        sigil = "SENTINTEL VALUE THAT IS A STRING"
        mock_hash = mock.Mock()
        mock_hash.digest = mock.Mock(return_value=sigil)
        mock_md5 = mock.Mock(return_value=mock_hash)
        # choose parameters so that key + salt is already desired length
        key = 'a'*8
        salt = 'b'*8
        T.assert_equal(crypt_util.pbkdf1(key, salt, key_size=16, count=4, hash_algo=mock_md5), (sigil[:-16], sigil[-16:]))
        T.assert_equal(mock_md5.mock_calls, [
            mock.call(key+salt),
            mock.call(sigil),
            mock.call(sigil),
            mock.call(sigil),
        ])


if __name__ == '__main__':
    T.run()
