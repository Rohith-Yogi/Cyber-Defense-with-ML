from pipeline.nfs.nfs import Model as Nfs
from pipeline.deepMalwareDetectionCore.src.deepMalwareDetectionFunc.test import Model as deepMalwareDetection
from pipeline.FFNN.model import Model as FFNN
import numpy as np


class Model:
    def __init__(self):
        self.models = [
            Nfs(),
            deepMalwareDetection(),
            FFNN()
        ]

    def predict_threshold(self, bytez, threshold=0.5) -> int:
        results = [model.predict_threshold(bytez, threshold) for model in self.models]

        return 1 if np.mean(results) >= threshold else 0


# if __name__ == '__main__':
#     model = Model()

# deepMalwareDetection()