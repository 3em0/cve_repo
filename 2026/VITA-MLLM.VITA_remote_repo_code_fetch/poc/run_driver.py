"""Consumer harness for the VITA-MLLM/VITA model-package reproduction.

Loads a model directory through the demo's own loader
(vita.model.builder.load_pretrained_model, the function video_audio_demo.py
calls) with device="cpu". The vulnerability trigger happens inside
VITAQwen2ForCausalLM.from_pretrained -> VITAMetaModel.__init__ ->
build_audio_encoder(config): the parsed config's mm_audio_encoder value is
resolved with transformers' get_file_from_repo() and train.yaml, global_cmvn
and final.pt are downloaded from the repository id it names, before final.pt
is handed to torch.load().
"""
import argparse
import os
import sys

os.environ.setdefault("HF_ENDPOINT", "http://127.0.0.1:8000")
sys.path.insert(0, "/opt/VITA")

print(f"[driver] HF_ENDPOINT = {os.environ['HF_ENDPOINT']} "
      f"(all HF-hub traffic is pinned to the local mock)")
print("[driver] importing vita.model.builder (registers the VITA model classes)")

from vita.model.builder import load_pretrained_model  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--arm", choices=["positive", "negative"], required=True)
args = parser.parse_args()

model_path = (
    "/work/poc/models/positive" if args.arm == "positive" else "/work/poc/models/negative"
)

print(f"[driver] arm={args.arm}  model_path={model_path}")
print("[driver] load_pretrained_model -> AutoTokenizer + VITAQwen2ForCausalLM.from_pretrained")
print("[driver] from_pretrained constructs VITAMetaModel; "
      "config.mm_audio_encoder drives build_audio_encoder")

tokenizer, model, image_processor, context_len = load_pretrained_model(
    model_path=model_path,
    model_base=None,
    model_name="VITA-1.5",
    model_type="qwen2p5_instruct",
    device="cpu",
)

audio_encoder = model.get_audio_encoder()
print(f"[driver] {args.arm}: MODEL CONSTRUCTED OK")
print(f"[driver] {args.arm}: audio_encoder = {type(audio_encoder).__name__}")
