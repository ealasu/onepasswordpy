import ctypes
import ctypes.util
import struct
from pprint import pprint

"""Simple ctypes wrapper around nettle. Idea came from https://github.com/fredrikt/python-ndnkdf"""


_nettle = ctypes.cdll.LoadLibrary(ctypes.util.find_library('nettle'))
for function in ('nettle_hmac_sha1_update', 'nettle_hmac_sha512_update', 'nettle_hmac_sha1_digest', 'nettle_hmac_sha512_digest'):
    if not hasattr(_nettle, function):
        raise ImportError(function)


def _pbkdf2(password, salt, length, iterations, hash_size, set_fn, update_fn, digest_fn):
    # TODO: 1024 bytes is almost definitely not the size of this structure
    shactx = ctypes.create_string_buffer('', size=1024)
    set_fn(ctypes.byref(shactx), len(password), password)
    
    U = ctypes.create_string_buffer('', size=64)
    T = ctypes.create_string_buffer('', size=64)
    
    generated_data = 0
    generated_chunks = []
    i = 1
    while generated_data < length:
        update_fn(ctypes.byref(shactx), len(salt), salt)
        update_fn(ctypes.byref(shactx), 4, struct.pack(">I", i))
        digest_fn(ctypes.byref(shactx), hash_size, ctypes.byref(T))
        prev = T
        for u in xrange(iterations - 1):
            update_fn(ctypes.byref(shactx), hash_size, ctypes.byref(prev))
            digest_fn(ctypes.byref(shactx), hash_size, ctypes.byref(U))
            _nettle.memxor(ctypes.byref(T), ctypes.byref(U), hash_size)
            prev = U
        generated_chunks.append(T[:hash_size])
        generated_data += hash_size
        i += 1
    return "".join(generated_chunks)[:length]

def pbkdf2_sha1(password, salt, length, iterations):
    return _pbkdf2(password, salt, length, iterations, 20, _nettle.nettle_hmac_sha1_set_key, _nettle.nettle_hmac_sha1_update, _nettle.nettle_hmac_sha1_digest)

def pbkdf2_sha512(password, salt, length, iterations):
    return _pbkdf2(password, salt, length, iterations, 64, _nettle.nettle_hmac_sha512_set_key, _nettle.nettle_hmac_sha512_update, _nettle.nettle_hmac_sha512_digest)
