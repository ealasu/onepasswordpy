import os.path

import testify as T

import onepassword.keychain

class AgileKeychainIntegrationTestCase(T.TestCase):
    test_file_root = os.path.realpath(os.path.join(__file__, '..', '..', '..', 'data', 'sample.agilekeychain'))

    def test_open(self):
        c = onepassword.keychain.AKeychain(self.test_file_root)
        c.unlock("george")
        items = sorted(c.items, key=lambda x: x.uuid)
        T.assert_equal(items[0].uuid, '23591BA807444B1EB5F356A807ED62F0')
        T.assert_equal(items[0]._decrypted, '{"notesPlain":"George wrote me!"}')
        T.assert_equal(items[1].uuid, 'A7E82B9E4EAB4F8BB14DC3C6C25EF6C8')
        T.assert_equal(items[1]._decrypted, '{"fields":[{"name":"Username","value":"george","designation":"username"},{"value":"george","name":"Password","designation":"password"}]}')


if __name__ == '__main__':
    T.run()

