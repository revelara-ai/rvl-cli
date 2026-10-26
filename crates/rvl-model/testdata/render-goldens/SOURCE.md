# Decision-model render goldens

rvl renders the decision model's input itself, and the rendering must be
byte-identical to the renderer the model was trained with, and tokenize to the
same ids (po-177qi.13). These files are copied from the model's training
repository (private) at commit 30022f4e9699, so a test here can check rvl's
renderer with no network:

- `render-goldens.jsonl`: 60 synthetic inputs (bound-question and frame rows,
  with and without each part of the input, each length cap) under both layouts,
  each with its rendered text and its token ids. Written by the training
  repository's goldens generator from `prepare.render_input`.
- `prepare.py`: the reference renderer (`render_input`, layout `compact` is the
  one the shipped model uses). A reference to read, not code rvl runs.
- `tokenizer.json`: the tokenizer of the shipped model, Hugging Face
  `jhu-clsp/ettin-encoder-32m` revision
  `1b8ba06455dd44f80fc9c1ca9e22806157a57379`, sha256
  `9fd55248d51d33976b324fc11592e28071da7d41e0e9401dfb7082e30574b7b1`. A test
  that reads it checks this sha256 first.

When the training renderer changes, copy all three again from the commit that
changed it, and update the commit above.
