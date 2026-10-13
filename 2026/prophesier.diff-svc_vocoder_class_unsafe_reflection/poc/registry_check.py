'''Diagnostic (optional): shows the intended allowlist of get_vocoder_cls() and
that the dotted form used by the project's own training/config.yaml can never
match it, so every documented deployment resolves the class with
importlib.import_module() + getattr().
'''
import network.vocoders.base_vocoder as b

SHIPPED = "network.vocoders.hifigan.HifiGAN"   # value in repo training/config.yaml
DOTTED_PWG = "network.vocoders.pwg.PWG"

print("registered VOCODERS keys           :", sorted(b.VOCODERS))
print("'PWG' in VOCODERS (registry branch):", "PWG" in b.VOCODERS)
print(f"'{DOTTED_PWG}' in VOCODERS:", DOTTED_PWG in b.VOCODERS)
print(f"'{SHIPPED}' in VOCODERS:", SHIPPED in b.VOCODERS)
print("-> the shipped dotted value always falls through to the importlib branch")
