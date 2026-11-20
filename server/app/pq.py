"""ML-DSA-65 (FIPS 204) through liboqs. The library is the Open Quantum Safe project's; nothing is implemented here, only calls.
liboqs is found via NOC_LIBOQS or the usual places (build it with tools/build-liboqs-host.sh)."""
import ctypes
import ctypes.util
import os

ALG = b"ML-DSA-65"
PK_LEN, SK_LEN, SIG_MAX = 1952, 4032, 3309
SUCCESS = 0


class PQUnavailable(RuntimeError):
    pass


def _candidates():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    if os.environ.get("NOC_LIBOQS"):
        yield os.environ["NOC_LIBOQS"]
    yield os.path.join(root, "third_party", "build-host", "lib", "liboqs.so")
    yield os.path.join(root, "third_party", "build-host", "lib", "liboqs.dylib")
    found = ctypes.util.find_library("oqs")
    if found:
        yield found
    yield "/usr/local/lib/liboqs.so"


_lib = None


def lib():
    global _lib
    if _lib is not None:
        return _lib
    for path in _candidates():
        try:
            c = ctypes.CDLL(path)
        except OSError:
            continue
        c.OQS_SIG_new.restype = ctypes.c_void_p
        c.OQS_SIG_new.argtypes = [ctypes.c_char_p]
        c.OQS_SIG_free.argtypes = [ctypes.c_void_p]
        c.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        c.OQS_SIG_sign.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        c.OQS_SIG_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        sig = c.OQS_SIG_new(ALG)
        if not sig:
            continue
        c.OQS_SIG_free(sig)
        _lib = c
        return c
    raise PQUnavailable("liboqs with ML-DSA-65 not found: run tools/build-liboqs-host.sh or set NOC_LIBOQS")


def available() -> bool:
    try:
        lib()
        return True
    except PQUnavailable:
        return False


class _Sig:
    def __enter__(self):
        self.c = lib()
        self.s = self.c.OQS_SIG_new(ALG)
        return self

    def __exit__(self, *a):
        self.c.OQS_SIG_free(self.s)


def keypair():
    """For tests only: the server never creates admin keys."""
    with _Sig() as g:
        pk, sk = ctypes.create_string_buffer(PK_LEN), ctypes.create_string_buffer(SK_LEN)
        if g.c.OQS_SIG_keypair(g.s, pk, sk) != SUCCESS:
            raise RuntimeError("keypair failed")
        return pk.raw, sk.raw


def sign(sk: bytes, msg: bytes) -> bytes:
    with _Sig() as g:
        out, n = ctypes.create_string_buffer(SIG_MAX), ctypes.c_size_t(0)
        if g.c.OQS_SIG_sign(g.s, out, ctypes.byref(n), msg, len(msg), sk) != SUCCESS:
            raise RuntimeError("sign failed")
        return out.raw[: n.value]


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pk) != PK_LEN or not (0 < len(sig) <= SIG_MAX):
        return False
    with _Sig() as g:
        return g.c.OQS_SIG_verify(g.s, msg, len(msg), sig, len(sig), pk) == SUCCESS
