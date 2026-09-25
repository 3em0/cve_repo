# ---------------------------------------------------------------------------
# llama.cpp mmproj trust-delegation ASan lab
#   bug 1 : clip.vision.feature_layer out-of-bounds READ (clip_graph_llava::build)
#   bug 2 : minicpmv bucket_coords[1024] stack out-of-bounds WRITE (clip_encode)
#
# The upstream source tree is supplied as the named build context `llamacpp_src`
# and is pinned to commit 3d82ef62d47fd74e18f36c5eccbdcf965b617b17 by the check
# below.  No source patching: clip.cpp's own load-time validation (get_arr_int
# type/arity checks, patch_size range check) is compiled in and running.
#
# Sanitizers are the project's own CMake switches, exactly like the original lab.
#
#   docker build --build-context llamacpp_src=<pinned tree> --build-context kit=<kit> \
#                -f Dockerfile -t llamacpp-mmproj-asan:3d82ef62 .
#   docker run --rm --security-opt seccomp=unconfined -v "<out>:/out" llamacpp-mmproj-asan:3d82ef62
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC
# The stock Debian mirror returned 502 during the first build; pin a stable mirror.
RUN set -eux; \
      sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
      apt-get update; \
      apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git file ca-certificates pkg-config \
        clang-16 llvm-16 python3 python3-venv; \
      rm -rf /var/lib/apt/lists/*; \
      clang-16 --version | head -n1

# Debian ships clang-16's sanitizer runtimes in a separate package; without it the
# link step fails with "cannot find libclang_rt.asan_static-x86_64.a".
RUN set -eux; \
      apt-get update; \
      apt-get install -y --no-install-recommends libclang-rt-16-dev; \
      rm -rf /var/lib/apt/lists/*; \
      ls -l /usr/lib/llvm-16/lib/clang/16/lib/linux/libclang_rt.asan_static-x86_64.a

RUN set -eux; \
      python3 -m venv /opt/venv; \
      /opt/venv/bin/pip install --no-cache-dir -q \
        -i https://pypi.tuna.tsinghua.edu.cn/simple \
        gguf==0.18.0 numpy==1.26.4; \
      /opt/venv/bin/python -c "import gguf, numpy; print('gguf/numpy ok', numpy.__version__)"
ENV PATH=/opt/venv/bin:$PATH

COPY --from=llamacpp_src / /src/llamacpp
RUN cd /src/llamacpp \
    && git rev-parse HEAD | tee /src/llamacpp_commit.txt \
    && test "$(cat /src/llamacpp_commit.txt)" = "3d82ef62d47fd74e18f36c5eccbdcf965b617b17"

RUN cd /src/llamacpp \
    && cmake -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_C_COMPILER=clang-16 -DCMAKE_CXX_COMPILER=clang++-16 \
        -DLLAMA_SANITIZE_ADDRESS=ON -DLLAMA_SANITIZE_UNDEFINED=ON \
        -DGGML_SANITIZE_ADDRESS=ON -DGGML_SANITIZE_UNDEFINED=ON \
        -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=OFF \
        -DLLAMA_BUILD_APP=OFF -DLLAMA_BUILD_UI=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
        -DGGML_NATIVE=OFF -DGGML_BACKEND_DL=OFF \
    && cmake --build build -j "$(nproc)" --target llama-mtmd-cli \
    && ls -la /src/llamacpp/build/bin/llama-mtmd-cli

# The attacker's entire capability is the mmproj GGUF; the victim text model is
# the victim's own file and is byte-identical in the positive and negative runs.
COPY --from=kit /artifact /artifact
COPY --from=kit /exp/drive.py /exp/drive.py

ENV ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-16
WORKDIR /work
# setarch -R disables ASLR for the process tree (AddressSanitizer vs. high
# vm.mmap_rnd_bits on modern kernels); needs --security-opt seccomp=unconfined.
ENTRYPOINT ["setarch", "-R", "/opt/venv/bin/python3", "/exp/drive.py"]
