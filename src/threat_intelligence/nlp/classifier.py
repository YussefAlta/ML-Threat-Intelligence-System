"""
SecureBERT 2.0 multi-label document classifier.

Fine-tunes cisco-ai/SecureBERT2.0-base for multi-label classification across
6 threat intelligence categories. Only used when weak supervision labels alone
do not achieve sufficient F1 (>= 0.7 threshold).

Training uses weak labels (from labeling function aggregation) as supervision.
"""

from typing import Dict, List, Optional, Tuple

LABEL_NAMES = [
    "vulnerability",
    "exploit",
    "phishing",
    "ransomware",
    "threat_actor",
    "ioc",
]


class SecureBERTClassifier:
    """
    Multi-label document classifier fine-tuned on SecureBERT 2.0.
    """

    def __init__(
        self,
        config: Optional[object] = None,
        model_name: Optional[str] = None,
        num_labels: int = 6,
        device: Optional[str] = None,
    ) -> None:
        self.config = config
        self.model_name = model_name
        if self.model_name is None and config is not None:
            self.model_name = getattr(
                config, "SECUREBERT_MODEL_NAME", "cisco-ai/SecureBERT2.0-base"
            )
        if self.model_name is None:
            self.model_name = "cisco-ai/SecureBERT2.0-base"
        self.num_labels = num_labels
        self.label_names = LABEL_NAMES
        self._device = device
        self._model = None
        self._tokenizer = None

    def _load_model(self) -> None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as e:
            raise ImportError(
                "SecureBERTClassifier requires transformers and torch. "
                "Install with: pip install transformers torch"
            ) from e

        if self._model is not None:
            return

        tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name,
            num_labels=self.num_labels,
        )
        model.config.problem_type = "multi_label_classification"

        device = self._device
        if device is None:
            device = "cuda" if torch.cuda.is_available() else "cpu"
        model = model.to(device)

        self._tokenizer = tokenizer
        self._model = model
        self._device = device

    def _get_device(self) -> str:
        if self._device is not None:
            return self._device
        try:
            import torch
            return "cuda" if torch.cuda.is_available() else "cpu"
        except ImportError:
            return "cpu"

    def prepare_dataset(
        self,
        documents: List[Dict],
        label_field: str = "predicted_labels",
        max_length: int = 512,
    ) -> Tuple[Dict, List[List[float]], List[int], List[int]]:
        """
        Convert corpus documents with predicted_labels to tokenized encodings
        and multi-hot label vectors.

        Returns:
            Tuple of (encodings dict, labels, train_indices, val_indices).
        """
        self._load_model()
        import random

        random.seed(42)
        indices = list(range(len(documents)))
        random.shuffle(indices)
        split = int(0.8 * len(indices))
        train_indices = indices[:split]
        val_indices = indices[split:]

        texts = []
        labels = []
        for doc in documents:
            title = doc.get("title", "") or ""
            content = doc.get("content", "") or ""
            text = f"{title} {content}".strip()
            texts.append(text)

            pred_labels = doc.get(label_field, {})
            if not isinstance(pred_labels, dict):
                pred_labels = {}
            multi_hot = [
                1.0 if label in pred_labels else 0.0 for label in self.label_names
            ]
            labels.append(multi_hot)

        encodings = self._tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors=None,
        )

        return encodings, labels, train_indices, val_indices

    def train(
        self,
        documents: List[Dict],
        epochs: int = 3,
        batch_size: int = 8,
        learning_rate: float = 2e-5,
        output_dir: str = "models/securebert_classifier",
    ) -> Dict:
        """
        Fine-tune the classifier on documents with weak labels.
        """
        try:
            from datasets import Dataset
            import numpy as np
            from sklearn.metrics import f1_score
        except ImportError as e:
            raise ImportError(
                "Training requires datasets, numpy, and scikit-learn. "
                "Install with: pip install datasets numpy scikit-learn"
            ) from e

        self._load_model()
        encodings, labels, train_idx, val_idx = self.prepare_dataset(documents)

        train_enc = {k: [v[i] for i in train_idx] for k, v in encodings.items()}
        train_labels = [labels[i] for i in train_idx]
        val_enc = {k: [v[i] for i in val_idx] for k, v in encodings.items()}
        val_labels = [labels[i] for i in val_idx]

        train_data = {**train_enc, "labels": train_labels}
        val_data = {**val_enc, "labels": val_labels}

        train_dataset = Dataset.from_dict(train_data)
        val_dataset = Dataset.from_dict(val_data)

        def compute_metrics(eval_pred):
            logits, labels_batch = eval_pred
            import numpy as np
            from sklearn.metrics import f1_score

            probs = 1.0 / (1.0 + np.exp(-logits))
            preds = (probs >= 0.5).astype(np.int64)
            f1_micro = float(f1_score(labels_batch, preds, average="micro", zero_division=0))
            f1_macro = float(f1_score(labels_batch, preds, average="macro", zero_division=0))
            return {"f1_micro": f1_micro, "f1_macro": f1_macro}

        from transformers import Trainer, TrainingArguments

        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            learning_rate=learning_rate,
            warmup_steps=100,
            weight_decay=0.01,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1_micro",
            greater_is_better=True,
        )

        trainer = Trainer(
            model=self._model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics,
        )

        result = trainer.train()
        trainer.save_model(output_dir)
        self._tokenizer.save_pretrained(output_dir)

        eval_result = trainer.evaluate()
        return {
            "train_loss": result.training_loss,
            "eval_metrics": eval_result,
        }

    def predict(self, texts: List[str]) -> List[Dict[str, float]]:
        """
        Run inference on texts; return list of {label_name: probability}.
        """
        self._load_model()
        import torch

        encodings = self._tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt",
        )
        encodings = {k: v.to(self._model.device) for k, v in encodings.items()}

        self._model.eval()
        with torch.no_grad():
            outputs = self._model(**encodings)
            logits = outputs.logits
            probs = torch.sigmoid(logits).cpu().numpy()

        results = []
        for prob_row in probs:
            result = {
                name: float(p) for name, p in zip(self.label_names, prob_row)
            }
            results.append(result)
        return results

    def predict_document(self, doc: Dict) -> Dict[str, float]:
        """Convenience method to predict a single document from title + content."""
        title = doc.get("title", "") or ""
        content = doc.get("content", "") or ""
        text = f"{title} {content}".strip()
        results = self.predict([text])
        return results[0]

    def load_model(self, model_dir: str) -> None:
        """Load a previously fine-tuned model from disk."""
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as e:
            raise ImportError(
                "Loading models requires transformers. "
                "Install with: pip install transformers torch"
            ) from e

        self._tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model_dir,
            num_labels=self.num_labels,
        )
        self._model.config.problem_type = "multi_label_classification"
        device = self._get_device()
        self._model = self._model.to(device)
        self._device = device

    @staticmethod
    def is_available() -> bool:
        """Check if transformers and torch are importable."""
        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401
            return True
        except ImportError:
            return False
