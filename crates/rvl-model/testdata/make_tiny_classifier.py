#!/usr/bin/env python3
"""Write the tiny ONNX classifier bundle the rvl-model tests run.

    python3 -I crates/rvl-model/testdata/make_tiny_classifier.py [outdir]

outdir defaults to tiny-classifier/ beside this script. It holds the files
a model bundle has (see crates/rvl-model/src/bundle.rs):

    model.onnx      the classifier graph, below
    tokenizer.json  a word-level tokenizer in the Hugging Face format
    bundle.json     model id, labels, temperature, max length
    cells.json      the cell id of each cell-head output

The graph is the shape of the decision model at toy size: token embedding,
mean pooling over the attention mask, one tanh layer, a linear verdict head
and a linear cell head.

    input_ids, attention_mask: int64 [batch, seq]
    logits:                    float [batch, 4]  violates, satisfies,
                                                 not_applicable, abstain
    cell_logits:               float [batch, 4]  M1, M2, S1, C1

Embedding dimension 0 carries the violation signal (+) and its opposite (-),
dimension 1 the not-applicable signal; every other word is zero on both, so
a long input full of unknown words still reads its few signal words.

The weights come from a fixed linear congruential generator, so the output is
byte-identical on every run and on every machine: rerun the script and `git
diff` shows nothing. The protobuf is written by hand because the script must
run with nothing but the standard library (no onnx or numpy package).
"""

import json
import os
import struct
import sys

VOCAB = [
    "[PAD]", "[UNK]",
    # Words that read as a bounded call (satisfies) ...
    "timeout", "deadline", "context", "cancel", "limit", "retry", "budget",
    # ... as an unbounded one (violates) ...
    "forever", "block", "wait", "loop", "sleep", "infinite", "hang",
    # ... and as code no rule applies to (not_applicable).
    "test", "mock", "fixture",
    # Filler.
    "client", "call", "the", "a", "with", "no", "http", "get",
]
LABELS = ["violates", "satisfies", "not_applicable", "abstain"]
CELLS = ["M1", "M2", "S1", "C1"]
DIM = 8
HIDDEN = 8
MAX_LENGTH = 64
TEMPERATURE = 1.5
MODEL_ID = "rvl-fixture/tiny-classifier"

# ONNX enums (onnx/onnx.proto).
FLOAT, INT64 = 1, 7
ATTR_INT = 2
IR_VERSION, OPSET = 8, 17


# --- protobuf wire format -------------------------------------------------


def varint(n):
    if n < 0:
        n += 1 << 64
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def key(field, wire):
    return varint(field << 3 | wire)


def f_int(field, n):
    return key(field, 0) + varint(n)


def f_bytes(field, data):
    if isinstance(data, str):
        data = data.encode()
    return key(field, 2) + varint(len(data)) + data


# --- ONNX messages --------------------------------------------------------


def tensor(name, dtype, dims, raw):
    return b"".join(
        [f_int(1, d) for d in dims] + [f_int(2, dtype), f_bytes(8, name), f_bytes(9, raw)]
    )


def floats(name, dims, values):
    return tensor(name, FLOAT, dims, struct.pack("<%df" % len(values), *values))


def int64s(name, dims, values):
    return tensor(name, INT64, dims, struct.pack("<%dq" % len(values), *values))


def attr_int(name, value):
    return f_bytes(1, name) + f_int(3, value) + f_int(20, ATTR_INT)


def node(op, inputs, outputs, *attrs):
    return b"".join(
        [f_bytes(1, i) for i in inputs]
        + [f_bytes(2, o) for o in outputs]
        + [f_bytes(3, outputs[0]), f_bytes(4, op)]
        + [f_bytes(5, a) for a in attrs]
    )


def value_info(name, dtype, dims):
    def dim(d):
        return f_bytes(1, f_bytes(2, d) if isinstance(d, str) else f_int(1, d))

    shape = b"".join(dim(d) for d in dims)
    tensor_type = f_int(1, dtype) + f_bytes(2, shape)
    return f_bytes(1, name) + f_bytes(2, f_bytes(1, tensor_type))


# --- weights --------------------------------------------------------------


class Lcg:
    """Numerical Recipes' 32-bit LCG: fixed, portable, no randomness."""

    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (1664525 * self.state + 1013904223) % (1 << 32)
        # A float32-exact value in [-0.5, 0.5).
        return (self.state >> 8) / float(1 << 24) - 0.5


def weights():
    rng = Lcg(20261019)
    bounded = set(VOCAB[2:9])
    unbounded = set(VOCAB[9:16])
    inapplicable = set(VOCAB[16:19])
    emb = []
    for word in VOCAB:
        row = [rng.next() for _ in range(DIM)]
        # Dimensions 0 and 1 carry the signals the heads read; the rest is
        # noise.
        row[0] = row[1] = 0.0
        if word in unbounded:
            row[0] = 2.0
        elif word in bounded:
            row[0] = -2.0
        elif word in inapplicable:
            row[1] = 2.0
        emb.extend(row)
    w1 = [rng.next() * 0.1 for _ in range(DIM * HIDDEN)]
    for i in range(DIM):
        w1[i * HIDDEN + 0] = w1[i * HIDDEN + 1] = 0.0
    w1[0 * HIDDEN + 0] = 20.0  # pooled[0] -> hidden[0], the violation signal
    w1[1 * HIDDEN + 1] = 20.0  # pooled[1] -> hidden[1], the not-applicable one
    b1 = [rng.next() * 0.1 for _ in range(HIDDEN)]
    b1[0] = b1[1] = 0.0

    def head(width, signals, bias):
        w = [rng.next() * 0.05 for _ in range(HIDDEN * width)]
        for (h, out), v in signals.items():
            w[h * width + out] = v
        return w, bias

    # hidden[0] -> violates (+) or satisfies (-), hidden[1] -> not_applicable;
    # abstain wins only when no signal word is read.
    w2, b2 = head(len(LABELS), {(0, 0): 4.0, (0, 1): -4.0, (1, 2): 6.0}, [0.0, 0.0, 0.0, 0.5])
    # The cell head: M1 and M2 follow violation (M1 the stronger), S1 its
    # opposite, C1 the not-applicable signal.
    wc, bc = head(len(CELLS), {(0, 0): 4.0, (0, 1): 3.0, (0, 2): -4.0, (1, 3): 6.0}, [0.0] * 4)
    # Round-trip through float32 so the bytes are what the values say.
    as_f32 = lambda xs: list(struct.unpack("<%df" % len(xs), struct.pack("<%df" % len(xs), *xs)))
    return [as_f32(x) for x in (emb, w1, b1, w2, b2, wc, bc)]


# --- the graph ------------------------------------------------------------


def model():
    emb, w1, b1, w2, b2, wc, bc = weights()
    nodes = [
        node("Gather", ["embedding", "input_ids"], ["tokens"]),
        node("Cast", ["attention_mask"], ["mask"], attr_int("to", FLOAT)),
        node("Unsqueeze", ["mask", "last_axis"], ["mask3"]),
        node("Mul", ["tokens", "mask3"], ["masked"]),
        node("ReduceSum", ["masked", "seq_axis"], ["summed"], attr_int("keepdims", 0)),
        node("ReduceSum", ["mask", "seq_axis"], ["count"], attr_int("keepdims", 1)),
        node("Max", ["count", "one"], ["count1"]),
        node("Div", ["summed", "count1"], ["pooled"]),
        node("MatMul", ["pooled", "w1"], ["h0"]),
        node("Add", ["h0", "b1"], ["h1"]),
        node("Tanh", ["h1"], ["hidden"]),
        node("MatMul", ["hidden", "w2"], ["l0"]),
        node("Add", ["l0", "b2"], ["logits"]),
        node("MatMul", ["hidden", "wc"], ["c0"]),
        node("Add", ["c0", "bc"], ["cell_logits"]),
    ]
    inits = [
        floats("embedding", [len(VOCAB), DIM], emb),
        floats("w1", [DIM, HIDDEN], w1),
        floats("b1", [HIDDEN], b1),
        floats("w2", [HIDDEN, len(LABELS)], w2),
        floats("b2", [len(LABELS)], b2),
        floats("wc", [HIDDEN, len(CELLS)], wc),
        floats("bc", [len(CELLS)], bc),
        floats("one", [], [1.0]),
        int64s("seq_axis", [1], [1]),
        int64s("last_axis", [1], [-1]),
    ]
    graph = b"".join(
        [f_bytes(1, n) for n in nodes]
        + [f_bytes(2, "tiny_classifier")]
        + [f_bytes(5, t) for t in inits]
        + [
            f_bytes(11, value_info("input_ids", INT64, ["batch", "seq"])),
            f_bytes(11, value_info("attention_mask", INT64, ["batch", "seq"])),
            f_bytes(12, value_info("logits", FLOAT, ["batch", len(LABELS)])),
            f_bytes(12, value_info("cell_logits", FLOAT, ["batch", len(CELLS)])),
        ]
    )
    opset = f_bytes(1, "") + f_int(2, OPSET)
    return (
        f_int(1, IR_VERSION)
        + f_bytes(2, "make_tiny_classifier.py")
        + f_bytes(7, graph)
        + f_bytes(8, opset)
    )


def tokenizer():
    return {
        "version": "1.0",
        "truncation": None,
        "padding": None,
        "added_tokens": [
            {"id": i, "content": t, "single_word": False, "lstrip": False,
             "rstrip": False, "normalized": False, "special": True}
            for i, t in enumerate(VOCAB[:2])
        ],
        "normalizer": {"type": "Lowercase"},
        "pre_tokenizer": {"type": "Whitespace"},
        "post_processor": None,
        "decoder": None,
        "model": {
            "type": "WordLevel",
            "vocab": {t: i for i, t in enumerate(VOCAB)},
            "unk_token": "[UNK]",
        },
    }


def bundle():
    return {
        "model_id": MODEL_ID,
        "labels": LABELS,
        "temperature": TEMPERATURE,
        "max_length": MAX_LENGTH,
        "pad_id": 0,
    }


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "tiny-classifier")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "model.onnx"), "wb") as f:
        f.write(model())
    cells = {"verdict_outputs": len(LABELS), "cells": CELLS}
    for name, doc in [("tokenizer.json", tokenizer()), ("bundle.json", bundle()), ("cells.json", cells)]:
        with open(os.path.join(out, name), "w") as f:
            json.dump(doc, f, indent=2, sort_keys=True)
            f.write("\n")


if __name__ == "__main__":
    main()
