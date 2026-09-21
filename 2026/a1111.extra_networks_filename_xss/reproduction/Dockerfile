FROM mbe2e/prod:a1111-82a973c0-browser
LABEL mbe2e=1
COPY artifact/pos/ /app/webui/models/Lora_pos/
COPY artifact/neg/ /app/webui/models/Lora_neg/
COPY config.json /app/webui/config.json
COPY treehash.py /work/treehash.py
COPY drive.py /work/drive.py
COPY entrypoint.sh /work/entrypoint.sh
RUN mkdir -p /out /evidence/logs && chmod +x /work/entrypoint.sh
WORKDIR /work
ENTRYPOINT ["/work/entrypoint.sh"]
