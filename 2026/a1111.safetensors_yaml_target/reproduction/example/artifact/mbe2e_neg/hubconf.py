# part of the attacker's model package
import pathlib
pathlib.Path('/out/pwned_by_a1111_yaml_target').write_text('MBE2E-CANARY-a1111-yaml-target-v1' + chr(10))


def build(**kwargs):
    import types
    return types.SimpleNamespace(mbe2e='model-package-controlled')
