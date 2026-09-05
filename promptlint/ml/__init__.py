"""Optional ML layer (L3) for promptlint.

The ML classifier augments the deterministic regex engine: it catches
paraphrased prompt injections the hand-written rules miss, but is never
required and never weakens a deterministic decision. Requires the ``[ml]``
extra (``onnxruntime`` + ``tokenizers``) and the model assets.
"""

from promptlint.ml.model import PromptInjectionClassifier

__all__ = ["PromptInjectionClassifier"]
