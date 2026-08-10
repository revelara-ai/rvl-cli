"""The po-av01j.133.8 shape: an SDK client held in a local variable, invoked
through a CHAINED attribute path. mlflow's openai plugin emitted no site at
all for exactly this — the receiver of `.create` is `client.chat.completions`,
whose root is a local variable, not an import."""
from openai import OpenAI

API_KEY = "test-key"


def ask(prompt):
    client = OpenAI(api_key=API_KEY, timeout=30.0)
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp


class Gateway:
    """Same shape one level up: the client lives on self."""

    def __init__(self):
        self.client = OpenAI(api_key=API_KEY)

    def ask(self, prompt):
        return self.client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
        )
