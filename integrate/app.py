import logging
from pipeline.model import Model
from pipeline.nfs.nfs import NeedForSpeedModel
import lief

from flask import Flask, request, jsonify
from gevent.pywsgi import WSGIServer

app = Flask(__name__)
app.config['model'] = Model()
THRESHOLD = 0.5

@app.route('/test', methods=['GET'])
def test():
    return "Hello World!"


@app.route('/', methods=['POST'])
def predict():  # put application's code here
    if request.headers['Content-Type'] != 'application/octet-stream':
        resp = jsonify({'error': 'expecting application/octet-stream'})
        resp.status_code = 400  # Bad Request
        return resp

    bytez = request.data

    try:
        model = app.config['model']

        # query the model
        result = model.predict_threshold(bytez, THRESHOLD)
    except (lief.bad_format, lief.read_out_of_bound) as e:
        print("Error:", e)
        result = 1

    if not isinstance(result, int) or result not in {0, 1}:
        resp = jsonify({'error': 'unexpected model result (not in [0,1])'})
        resp.status_code = 500  # Internal Server Error
        return resp

    resp = jsonify({'result': result})
    resp.status_code = 200
    return resp

if __name__ == '__main__':
    from gevent.pywsgi import WSGIServer

    print('starting server...')

    http_server = WSGIServer(('', 8080), app)
    http_server.serve_forever()


# from pipeline.deepMalwareDetectionCore.src.deepMalwareDetectionFunc.test import deepMalwareDetection
# deepMalwareDetection("pipeline/deepMalwareDetectionCore/assets/checkpoints/malconv_plus_50.pt","pipeline/deepMalwareDetectionCore/data/dll/") #this is goodware 
# deepMalwareDetection("pipeline/deepMalwareDetectionCore/assets/checkpoints/malconv_plus_50.pt","pipeline/deepMalwareDetectionCore/data/dasmalwerk/") #this is malware file
