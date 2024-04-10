from pipeline.nfs.nfs import Model as Nfs
from pipeline.deepMalwareDetectionCore.src.deepMalwareDetectionFunc.test import Model as deepMalwareDetection
import numpy as np


class Model:
    def __init__(self):
        self.models = [
            Nfs(),
            deepMalwareDetection()
        ]

    def predict_threshold(self, bytez, threshold=0.8) -> int:
        results = [model.predict_threshold(bytez, threshold) for model in self.models]

        return 1 if np.mean(results) >= threshold else 0


# if __name__ == '__main__':
#     model = Model()

# deepMalwareDetection()