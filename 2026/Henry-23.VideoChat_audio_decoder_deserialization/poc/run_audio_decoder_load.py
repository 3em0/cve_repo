#!/usr/bin/env python3
"""Reproduction harness for Henry-23/VideoChat @ 303681e.

Drives the real constructor of the affected component - class AudioDecoder in
src/GLM_4_Voice/flow_inference.py (lines 19-30) - exactly as VideoChat's
src/glm.py GLM_4_Voice.load_weights() does at startup:

    with open(config_path, 'r') as f:
        self.scratch_configs = load_hyperpyyaml(f)          # line 24 - sink
    ...
    self.flow = self.scratch_configs['flow']                # line 27
    self.flow.load_state_dict(torch.load(flow_ckpt_path, ...))  # line 28

No GLM-4-Voice checkpoints (flow.pt / hift.pt) are shipped with this PoC, so
after the YAML load the constructor stops at line 28 with an AttributeError
('int' object / 'dict' object has no attribute 'load_state_dict').
That crash is expected and is part of the evidence: it proves the run reached
line 27-28, while the security-relevant event happened earlier, during
load_hyperpyyaml() at line 24 - the canary file written by the attack sample.

Usage (from the root of the pinned VideoChat tree):
    python run_audio_decoder_load.py weights/ZhipuAI/glm-4-voice-decoder/config.yaml
    python run_audio_decoder_load.py weights/ZhipuAI/glm-4-voice-decoder/config.benign.yaml
"""
import sys

from src.GLM_4_Voice.flow_inference import AudioDecoder


def main():
    if len(sys.argv) != 2:
        print("usage: python run_audio_decoder_load.py <config.yaml>")
        return 2
    config_path = sys.argv[1]
    print(f"[harness] AudioDecoder(config_path={config_path}, device=cpu)")
    AudioDecoder(
        config_path=config_path,
        flow_ckpt_path="weights/ZhipuAI/glm-4-voice-decoder/flow.pt",
        hift_ckpt_path="weights/ZhipuAI/glm-4-voice-decoder/hift.pt",
        device="cpu",
    )
    print("[harness] constructor returned (not expected without checkpoints)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
