# praat.whisper_ggml_ndims_stack_oob — self-contained reproduction image.
#
# Upstream praat/praat (renamed praat/praat.github.io) at a pinned commit, built
# with the project's OWN makefile in its OWN headless configuration
# (PRAAT_GRAPHICS=barren PRAAT_AUDIO=none -> the praat_barren binary).
# No source patching: the vendored whisper.cpp loader is compiled exactly as
# shipped, and the build asserts that upstream's `n_dims > 4` guard is genuinely
# absent from external/whispercpp/whisper.cpp.
#
# Sanitiser flags are supplied through the ENVIRONMENT, not the make command
# line, because the Linux section of the Makefile uses `CFLAGS += ...` /
# `CXXFLAGS += ...` — a command-line assignment would replace the project's own
# flags instead of adding to them.
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git python3 llvm-14 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s /usr/bin/llvm-symbolizer-14 /usr/bin/llvm-symbolizer

# praat vendors zlib without the generated zconf.h; zlib.h #includes it and the
# build resolves it through the system include path.  The reference
# verification environment provided it via a system zlib installation
# (/usr/include/zconf.h); this checked-in copy is zlib v1.2.11's zconf.h with
# HAVE_UNISTD_H configured on as ./configure does for an installed zlib on
# Linux (sha256 e3b89e3938bd893cf119db106b57a10687915b2ef881ecc2c775ab6fddd88870),
# placed at the same location, so the build does not depend on apt mirror
# availability.  No praat source file is touched.
COPY zconf-system.h /usr/include/zconf.h

COPY praat-b753a09b /src/praat

RUN cd /src/praat && git rev-parse HEAD | tee /src/praat_commit.txt \
 && test "$(cat /src/praat_commit.txt)" = "b753a09ba0f4c2385735f08dacd2086088094d69" \
 && ! grep -q "n_dims > 4" external/whispercpp/whisper.cpp

ENV CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
    CXXFLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
    LDFLAGS="-fsanitize=address" \
    ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer

RUN cd /src/praat && make PRAAT_GRAPHICS=barren PRAAT_AUDIO=none -j "$(nproc)" \
 && ls -la /src/praat/praat_barren

COPY artifact /artifact
COPY exp /exp
COPY exp/expected.json /artifact/expected.json
RUN chmod +x /exp/run_one.sh

WORKDIR /work
ENTRYPOINT ["python3", "/exp/drive.py"]
