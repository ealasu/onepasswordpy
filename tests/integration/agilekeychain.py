import os.path

import testify as T

import onepassword.keychain

class AgileKeychainIntegrationTestCase(T.TestCase):
    test_file_root = os.path.realpath(os.path.join(__file__, '..', '..', '..', 'data', 'sample.agilekeychain'))

    def test_open(self):
        c = onepassword.keychain.AKeychain(self.test_file_root)
        c.unlock("george")
        assert c.items[0]._decrypted == '{"notesPlain":"George wrote me!"}'
        assert c.items[1]._decrypted == '{"fields":[{"name":"Username","value":"george","designation":"username"},{"value":"george","name":"Password","designation":"password"}]}'


if __name__ == '__main__':
    T.run()

