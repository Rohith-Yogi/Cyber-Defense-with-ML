from pipeline.nfs.nfs import Model as Nfs
from pipeline.deepMalwareDetectionCore.src.deepMalwareDetectionFunc.test import MalConvPlus_model as MalConvPlus_model
from pipeline.deepMalwareDetectionCore.src.deepMalwareDetectionFunc.test import MalConvBase_model as MalConvBase_model
from pipeline.deepMalwareDetectionCore.src.deepMalwareDetectionFunc.test import AttentionRCNN_model as AttentionRCNN_model
from pipeline.FFNN.model import Model as FFNN
import numpy as np

# All for 0.6 threshold - on the test data https://drive.google.com/file/d/16n_wlyAnAHL1aIHgnkbbIEjQ0SM2R259/view 
# Model - gooware% malware%. - check set wise results for goodware and malware (vishal) - pick best one
# Malcov+, 2xFFNN 98.75% and 90.03%. 
# only FFNN 97.81% and 92.21% 
# Malcov+, attention, 3xFFNN 97.81 and 91.59
# Malcov+, attention, 2xFFNN 91.8 and 89.41
# MalCov+, Attention and FFNN 85% and 87%
# (our submitted model ->) 2xMalcov+, FFNN 86.25% and 79.44%
# All models 83% gw and 83% mw
# Malcov+ and attention 80 and 80
# MalCoV+, base and attention 81.88% and 74.7%
# only Malcov+ 81.88 and 75.70 
# only attention 77.50 and 86.92
# NFS, Malcov+, Attention 77% and 85%
# only Malcov base 86.88% and 60.12
# only NFS 40% and 87.54%

class Model:
    def __init__(self):
        self.models = [
            # Nfs(),
            MalConvPlus_model(),
            # MalConvBase_model(),
            AttentionRCNN_model(),
            FFNN(),
        ]

    def predict_threshold(self, bytez, threshold=0.5) -> int:
        results = [model.predict_threshold(bytez, threshold) for model in self.models]
        # results.append(results[-1])
        # results.append(results[-1])
        # print(results)
        return 1 if np.mean(results) >= threshold else 0


# if __name__ == '__main__':
#     model = Model()

# deepMalwareDetection()l