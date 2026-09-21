# Per-root image for a1111.sshs_hash_xss_staged_rce.
# The positive package goes to A1111's DEFAULT LoRA directory, because that is the
# path the payload hardcodes -- an attacker writing this payload targets the stock
# install layout, not a flag we chose.
FROM mbe2e/prod:a1111-82a973c0-browser
LABEL mbe2e=1
COPY artifact/pos/ /app/webui/models/Lora/
COPY artifact/neg/ /app/webui/models/Lora_neg/
# stock user setting: "always show all networks on the Lora page". Without it the
# card builder dereferences shared.sd_model, which raises because this root needs
# no checkpoint at all. It does not touch the taint path.
COPY config.json /app/webui/config.json
COPY treehash.py /work/treehash.py
COPY drive.py /work/drive.py
COPY entrypoint.sh /work/entrypoint.sh
RUN mkdir -p /out /evidence/logs && chmod +x /work/entrypoint.sh
WORKDIR /work
ENTRYPOINT ["/work/entrypoint.sh"]
