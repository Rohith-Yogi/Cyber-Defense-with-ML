# Neural Network Malware Binary Classification

PyTorch implementation of [Malware Detection by Eating a Whole EXE](https://arxiv.org/abs/1710.09435), [Learning the PE Header, Malware Detection with Minimal Domain Knowledge](https://arxiv.org/abs/1709.01471), and other derived models for malware detection.

All model checkpoints are available at [`assets/checkpoints`](assets/checkpoints).

## Quickstart

1. Clone this repository via

```
$ git clone https://github.com/jaketae/deep-malware-detection.git
$ cd pytorch-malware-detection
```

2. Create a Python virtual environment and install dependencies.

```
$ python -m venv venv
$ source venv/bin/activate
$ pip install -U pip wheel # update pip
$ pip install -r requirements.txt
```

3. Prepare PE files. `src/bin` provides scrapers to download malware. For instance, to download files from [dalswerk](https://das-malwerk.herokuapp.com), run

```
$ python -m src.bin.dasmalwerk
```

By default, this will download the files under the `raw` folder of the root directory.

4. Train the model.

```
$ cd src/deep_malware_detection
$ python train.py --benign_dir=YOUR_PATH_TO_BENIGN --malware_dir=YOUR_PATH_TO_MALWARE
```

## Data

```
python -m src.bin.malshare - NOT WORKING


python -m src.bin.dll
python extract_header.py --input_dir="../../raw/dll/" --output_dir="../../data/dll/"

python -m src.bin.dasmalwerk
python extract_header.py --input_dir="../../raw/dasmalwerk/" --output_dir="../../data/dasmalwerk/"

python train.py --benign_dir="../../raw/dll/" --malware_dir="../../raw/dasmalwerk/" - ERROR [Unpickling](https://github.com/jaketae/deep-malware-detection/issues/2)
```

This project was developed in late 2020, and unfortunately I lost access to the server where I collected data and ran experiments. While replicating all training data exactly may be infeasible, here are some resources for data collection.

1. [Wikidll.com](https://wikidll.com): Online website with downloadable benign `.dll` files. [Scraper](src/bin/dll.py).
2. [Dasmalwerk](https://das-malwerk.herokuapp.com): Online website with downloadable malware for research. [Scraper](src/bin/dasmalwerk.py).
3. [Malshare.com](https://malshare.com): Online website with downloadable malware for research. [Scraper](src/bin/malshare.py).
4. [EMBER](https://github.com/elastic/ember): Open dataset for malware detection research.
5. [Kaggle dataset](https://www.kaggle.com/datasets/amauricio/pe-files-malwares): PE file dataset availalbe on Kaggle, including both benign and malicious files.


## Implementation Notes

1. While Raff et. al used LSTMs for the sequential model, we tested both GRU and LSTMs and found that the former was easier to train.
2. We combined models presented in the two papers to derive a custom model that uses concatenated feature vector produced by the entry point 1D-CNN layer as well as the RNN units that follow. We denote these custom models with a "Res" prefix in the table below.
3. We also further develop the attention-based model in Raff et. al with this residual approach.
4. Due to computational constraints, we decided to only use PE file headers up to their 4096th bytes, thus creating a 4096 dimensional sequential feature vector for every file.

## Results

Epoch [1/50], Train Loss: 0.4208, Val Loss: 0.3733                                                                                                                                                                               
Epoch [2/50], Train Loss: 0.4191, Val Loss: 0.3749                                                                                                                                                                               
Epoch [3/50], Train Loss: 0.3641, Val Loss: 0.2909                                                                                                                                                                               
Epoch [4/50], Train Loss: 0.3144, Val Loss: 0.2786                                                                                                                                                                               
Epoch [5/50], Train Loss: 0.2714, Val Loss: 0.2657                                                                                                                                                                               
Epoch [6/50], Train Loss: 0.2497, Val Loss: 0.2654                                                                                                                                                                               
Epoch [7/50], Train Loss: 0.2023, Val Loss: 0.3499                                                                                                                                                                               
Epoch [8/50], Train Loss: 0.1789, Val Loss: 0.2578                                                                                                                                                                               
Epoch [9/50], Train Loss: 0.1554, Val Loss: 0.2296                                                                                                                                                                               
Epoch [10/50], Train Loss: 0.1606, Val Loss: 0.2217                                                                                                                                                                              
Epoch [11/50], Train Loss: 0.1339, Val Loss: 0.2341                                                                                                                                                                              
Epoch [12/50], Train Loss: 0.0968, Val Loss: 0.2820                                                                                                                                                                              
Epoch [13/50], Train Loss: 0.0910, Val Loss: 0.6367                                                                                                                                                                              
Epoch [14/50], Train Loss: 0.0819, Val Loss: 0.2369                                                                                                                                                                              
Epoch [15/50], Train Loss: 0.0622, Val Loss: 0.3032                                                                                                                                                                              
Epoch [16/50], Train Loss: 0.0841, Val Loss: 0.2183                                                                                                                                                                              
Epoch [17/50], Train Loss: 0.0642, Val Loss: 0.2487                                                                                                                                                                              
Epoch [18/50], Train Loss: 0.0817, Val Loss: 0.2137                                                                                                                                                                              
Epoch [19/50], Train Loss: 0.0543, Val Loss: 0.4120                                                                                                                                                                              
Epoch [20/50], Train Loss: 0.0493, Val Loss: 0.2121                                                                                                                                                                              
Epoch [21/50], Train Loss: 0.0373, Val Loss: 0.2915                                                                                                                                                                              
Epoch [22/50], Train Loss: 0.0392, Val Loss: 0.3014                                                                                                                                                                              
Epoch [23/50], Train Loss: 0.0278, Val Loss: 0.3115                                                                                                                                                                              
Epoch [24/50], Train Loss: 0.0484, Val Loss: 0.2984                                                                                                                                                                              
Epoch [25/50], Train Loss: 0.0380, Val Loss: 0.3232                                                                                                                                                                              
Epoch [26/50], Train Loss: 0.0341, Val Loss: 0.2630                                                                                                                                                                              
Epoch [27/50], Train Loss: 0.0294, Val Loss: 0.2258                                                                                                                                                                              
Epoch [28/50], Train Loss: 0.0347, Val Loss: 0.2428                                                                                                                                                                              
Epoch [29/50], Train Loss: 0.0220, Val Loss: 0.2492                                                                                                                                                                              
Epoch [30/50], Train Loss: 0.0229, Val Loss: 0.2749                                                                                                                                                                              
Epoch [31/50], Train Loss: 0.0177, Val Loss: 0.2663                                                                                                                                                                              
Epoch [32/50], Train Loss: 0.0190, Val Loss: 0.2743                                                                                                                                                                              
Epoch [33/50], Train Loss: 0.0319, Val Loss: 0.2472                                                                                                                                                                              
Epoch [34/50], Train Loss: 0.0204, Val Loss: 0.2442                                                                                                                                                                              
Epoch [35/50], Train Loss: 0.0243, Val Loss: 0.2705                                                                                                                                                                              
Epoch [36/50], Train Loss: 0.0254, Val Loss: 0.2551                                                                                                                                                                              
Epoch [37/50], Train Loss: 0.0250, Val Loss: 0.2492                                                                                                                                                                              
Epoch [38/50], Train Loss: 0.0194, Val Loss: 0.2547                                                                                                                                                                              
Epoch [39/50], Train Loss: 0.0199, Val Loss: 0.2762                                                                                                                                                                              
Epoch [40/50], Train Loss: 0.0222, Val Loss: 0.2525                                                                                                                                                                              
Epoch [41/50], Train Loss: 0.0258, Val Loss: 0.2580                                                                                                                                                                              
Epoch [42/50], Train Loss: 0.0271, Val Loss: 0.2451                                                                                                                                                                              
Epoch [43/50], Train Loss: 0.0219, Val Loss: 0.2507                                                                                                                                                                              
Epoch [44/50], Train Loss: 0.0198, Val Loss: 0.2491                                                                                                                                                                              
Epoch [45/50], Train Loss: 0.0315, Val Loss: 0.2512                                                                                                                                                                              
Epoch [46/50], Train Loss: 0.0139, Val Loss: 0.2571                                                                                                                                                                              
Epoch [47/50], Train Loss: 0.0283, Val Loss: 0.2538                                                                                                                                                                              
Epoch [48/50], Train Loss: 0.0276, Val Loss: 0.2596                                                                                                                                                                              
Epoch [49/50], Train Loss: 0.0183, Val Loss: 0.2607                                                                                                                                                                              
Epoch [50/50], Train Loss: 0.0213, Val Loss: 0.2606

Presented below is a table detailing the performance of each model.

| Architecture   | Acc | F1   |
| -------------- | --- | ---- |
| MalConvBase    | 91  | .931 |
| MalConv+       | 94  | .951 |
| MalConv+ (E16) | 93  | .944 |
| MalConv+ (W64) | 94  | .949 |
| MC+ (E16,W64)  | 94  | .950 |
| MC+ (C256)     | 91  | .930 |
| GRU-CNN        | 93  | .946 |
| BiGRU-CNN      | 91  | .931 |
| GRU-CNN (H128) | 93  | .946 |
| ResGRU-CNN     | 94  | .948 |
| AttnGRU-CNN    | 94  | .952 |
| AttnResGRU-CNN | 94  | .952 |

For visualizations of training and model evaluation, refer to images in the `figures` directory.

## Contributing

The coding style is dictated by [black](https://black.readthedocs.io/en/stable/) and [isort](https://pycqa.github.io/isort/). You can apply them via 

```
# pip install black isort
make style
```

Please feel free to submit issues or pull requests.

## Citation

If you find this repository helpful for your research, please cite as follows.

```
@misc{dmd,
	title        = {Deep Malware Detection: A neural approach to malware detection in portable executables},
	author       = {Tae, Jaesung},
	year         = 2020,
	howpublished = {\url{https://github.com/jaketae/deep-malware-detection}}
}
```

## References

```
@misc{raff2017malware,
	title        = {Malware Detection by Eating a Whole EXE},
	author       = {Edward Raff and Jon Barker and Jared Sylvester and Robert Brandon and Bryan Catanzaro and Charles Nicholas},
	year         = 2017,
	eprint       = {1710.09435},
	archiveprefix = {arXiv},
	primaryclass = {stat.ML}
}
@article{Raff_2017,
	title        = {Learning the PE Header, Malware Detection with Minimal Domain Knowledge},
	author       = {Raff, Edward and Sylvester, Jared and Nicholas, Charles},
	year         = 2017,
	journal      = {Proceedings of the 10th ACM Workshop on Artificial Intelligence and Security - AISec  ’17},
	publisher    = {ACM Press},
	doi          = {10.1145/3128572.3140442},
	isbn         = 9781450352024,
	url          = {http://dx.doi.org/10.1145/3128572.3140442}
}
```

## License

Released under the [MIT License](LICENSE).
