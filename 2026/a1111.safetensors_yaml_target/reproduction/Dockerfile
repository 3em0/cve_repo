# Per-root image for a1111.safetensors_yaml_target.
# The ONLY thing added on top of the pinned product image is the attacker's
# model package (example/artifact/), dropped into A1111's checkpoint directory
# exactly as a victim would after unpacking a download, plus the out-of-process
# drive script.
FROM mbe2e/prod:a1111-82a973c0
LABEL mbe2e=1
COPY artifact/ /app/webui/models/Stable-diffusion/
COPY drive.py /work/drive.py
COPY entrypoint.sh /work/entrypoint.sh
RUN mkdir -p /out /evidence/logs && chmod +x /work/entrypoint.sh
WORKDIR /work
ENTRYPOINT ["/work/entrypoint.sh"]
