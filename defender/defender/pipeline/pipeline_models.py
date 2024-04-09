from defender.defender.nfs.nfs import Model as NfsModel
from collections import Counter


class Model:
    def __init__(self):
        self.models = [
            NfsModel(),
            NfsModel()
        ]

    def predict_threshold(self, bytez, threshold=0.8):
        results = [model.predict_threshold(bytez, threshold) for model in self.models]

        counts = Counter(results)

        if counts.get(1, 0) >= counts.get(0, 0):
            return 1

        return 0