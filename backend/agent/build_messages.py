# backend/agent/build_messages.py
import json
import os
from agent.window_reader import iter_jsonl
from agent.message_builder import build_message

def build_messages(input_jsonl: str, output_jsonl: str) -> int:
    os.makedirs(os.path.dirname(output_jsonl), exist_ok=True)
    n = 0
    with open(output_jsonl, "w", encoding="utf-8") as fout:
        for window in iter_jsonl(input_jsonl):
            msg = build_message(window)
            fout.write(json.dumps(msg, ensure_ascii=False) + "\n")
            n += 1
    return n

if __name__ == "__main__":
    job_id = "20260222_165812"  # 改成你的 job_id
    base = f"/home/os/FinalCode/malblock/backend/jobs/{job_id}"
    inp = os.path.join(base, "llm_inputs_selected.jsonl")
    out = os.path.join(base, "llm_messages.jsonl")

    total = build_messages(inp, out)
    print(f"built {total} messages -> {out}")