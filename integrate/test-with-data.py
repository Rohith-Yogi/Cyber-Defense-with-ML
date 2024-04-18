import re
import time
import zipfile
from typing import Tuple, Union, Dict
import json

import tqdm
import requests as rq
from pipeline.model import Model
from pipeline.nfs.nfs import NeedForSpeedModel


def stats(results: Dict[str, int]) -> Tuple[float, int]:
    acc = (sum([1 for value in results.values() if value == 1]) / (len(results) + 1e-8)) * 100
    defaults = sum([1 for value in results.values() if value == -1])

    return acc, defaults


def pretty_print(results: Dict[str, int], goodware: bool=True) -> None:
    if goodware:
        groups = set([re.search(r'gw(\d+)', key).group(0) for key in results])
    else:
        groups = set([re.search(r'mw(\d+)', key).group(0) for key in results])


    for group in groups:
        sample = {
            key: value for key, value in results.items() if f'/{group}/' in key
        }

        acc, defaults = stats(sample)

        if goodware:
            acc = 100 - acc

        print(
            f'{"benign" if goodware else "malware"} | group: {group} | Accuracy: {acc:.2f}% | Defaults: {defaults} | #samples: {len(sample)}')





if __name__ == '__main__':
    data_path = 'test-data/z-data.zip'
    url = "http://127.0.0.1:8080"

    results = {}
    password = b'infected'
    sample_size = 100000
    model = Model()
    threshold = 0.6
    online = False

    with zipfile.ZipFile(data_path, 'r') as f:
        with tqdm.tqdm(total=min(len(f.infolist()), sample_size), desc='Processing') as pbar:
            for info in f.infolist():
                if (not info.is_dir()) and sample_size > 0:

                    try:
                        if not online:
                            content = f.read(info.filename, pwd=b'infected')
                            results[info.filename] = model.predict_threshold(content, threshold)
                        else:
                            resp = rq.post(url, headers={'Content-Type': 'application/octet-stream'}, data=content, timeout=5)

                            if resp.status_code == 200:
                                results[info.filename] = resp.json()['result']
                            else:
                                results[info.filename] = 0

                    except Exception as e:
                        print(e)
                        results[info.filename] = -1

                    sample_size -= 1
                    pbar.update(1)

                    if sample_size == 0:
                        break

    with open('output.json', 'w') as f:
        json.dump(results, f, indent=4)

    # with open('output.json', 'r') as f:
    #     results = json.load(f)

    # process results
    goodware_results = {
        key: value for key, value in results.items() if '/gw' in key
    }

    malware_results = {
        key: value for key, value in results.items() if '/mw' in key
    }

    g_acc = pretty_print(goodware_results, True)
    m_acc = pretty_print(malware_results, False)

