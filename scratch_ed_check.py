import time
from iso_drill import ed25519 as ed

V1_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
V1_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
V1_SIG = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
          "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

t0 = time.perf_counter()
pub = ed.public_key(V1_SEED)
print("pub ok:", pub.hex() == V1_PUB, f"({(time.perf_counter()-t0)*1000:.0f} ms)")
t0 = time.perf_counter()
sig = ed.sign(V1_SEED, b"")
print("sig ok:", sig.hex() == V1_SIG, f"({(time.perf_counter()-t0)*1000:.0f} ms)")
t0 = time.perf_counter()
print("verify ok:", ed.verify(pub, b"", sig), f"({(time.perf_counter()-t0)*1000:.0f} ms)")
print("tamper rejected:", not ed.verify(pub, b"x", sig))

V2_SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
V2_PUB = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
V2_MSG = bytes.fromhex("72")
V2_SIG = ("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
          "a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
pub2 = ed.public_key(V2_SEED)
sig2 = ed.sign(V2_SEED, V2_MSG)
print("v2 pub ok:", pub2.hex() == V2_PUB)
print("v2 sig ok:", sig2.hex() == V2_SIG)
print("v2 verify:", ed.verify(pub2, V2_MSG, sig2))
