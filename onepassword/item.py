import simplejson
import base64


class AItem(object):
    def __init__(self, keychain):
        self.keychain = keychain

    @classmethod
    def new_from_file(cls, path, keychain):
        o = cls(keychain)
        o.load_from(path)
        return o

    def load_from(self, path):
        with open(path, "r") as f:
            data = simplejson.load(f)
        self.uuid = data['uuid']
        self.data = data
        if 'keyID' in data:
            identifier = data['keyID']
        elif 'securityLevel' in data:
            identifier = self.keychain.levels[data['securityLevel']]
        else:
            raise KeyError("Neither keyID or securityLevel present in %s" % self.uuid)
        self.key_identifier = identifier
        self._decrypted = self.keychain.decrypt(identifier, base64.b64decode(data['encrypted']))

    def __repr__(self):
        return '%s<uuid=%s, keyid=%s>' % (self.__class__.__name__, self.uuid, self.key_identifier)
