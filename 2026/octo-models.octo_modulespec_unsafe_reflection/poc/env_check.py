#!/usr/bin/env python3
"""Print the exact stack the reproduction runs on."""
import importlib.metadata as md
import platform

import flax
import jax
import orbax.checkpoint  # noqa: F401
import tensorflow as tf

import octo

print("python  ", platform.python_version(), "on", platform.system(), platform.release())
print("jax     ", jax.__version__, "(jaxlib", jax.lib.__version__ + ")")
print("flax    ", flax.__version__)
print("tensorflow", tf.__version__)
print("orbax   ", md.version("orbax-checkpoint"))
print("octo    ", octo.__file__)
