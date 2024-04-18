from keras.layers import Input, Dense, Flatten, Activation, BatchNormalization, LeakyReLU, Dropout, Maximum, Concatenate
from keras.models import Model, load_model
from keras import callbacks
# from keras.optimizers import Adam
from tensorflow.keras.optimizers.legacy import Adam, SGD
# from tensorflow.keras import backend as K
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn import linear_model, svm, tree
from sklearn.model_selection import train_test_split
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import tensorflow as tf
import argparse
import _pickle as cPickle
import gzip
import os, sys
import pickle
import re
import math
import lief
import pandas as pd
import zipfile
import tempfile
import json
import random
import time
import copy

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--train", nargs = 3, help="--train <malware_dir> <goodware_dir> <num_features>")
parser.add_argument("-p", "--test", nargs = 2, help="--test <file> <num_features>")
args = parser.parse_args()

train_size = 22868

if args.train is not None:
    train_files = {}

class PEAttributeExtractor():

    libraries = ""
    functions = ""
    exports = ""

    # initialize extractor
    def __init__(self, bytez):
        # save bytes
        self.bytez = bytez
        # parse using lief
        self.lief_binary = lief.PE.parse(list(bytez))
        # attributes
        self.attributes = {}
        self.grouped_data = {}
    
    # extract attributes
    def extract(self):
        
        # get imported libraries and functions
        if self.lief_binary.has_imports:
            self.libraries = " ".join([l for l in self.lief_binary.libraries])
            # self.functions = " ".join([f.name for f in self.lief_binary.imported_functions])
        self.functions = []
        self.grouped_data.update({"libraries": {}})
        for imported_library in self.lief_binary.imports:
              self.grouped_data["libraries"].update({imported_library.name: []})
              for func in imported_library.entries:
                if not func.is_ordinal:
                  self.grouped_data["libraries"][imported_library.name].append(func.name)
                  self.functions.append(func.name)
        self.functions = " ".join(self.functions)
        
        self.attributes.update({"functions": self.functions, "libraries": self.libraries})

        # get exports
        # if self.lief_binary.has_exports:
        #     self.exports = [f.name for f in self.lief_binary.exported_functions]
        self.grouped_data.update({"exports_list": self.exports})
        self.exports = " ".join(self.exports)
        self.attributes.update({"exports_list": self.exports})

        return (self.attributes, self.grouped_data)

class FeatureExtractor():

    def feature_extractor_dir(self, sampled_files, label, return_after_grouping = 0):
        # if not os.path.exists(input_dir):
        #   print("!!!INPUT DIR (" + input_dir + ") NOT FOUND!!!")
        #   return
        data = []
        grouped_data = {"libraries": {}, "exports_list":[]}
        for _file in sampled_files:
          filepath = _file
          try:
            pe_att_ext = PEAttributeExtractor(open(filepath,'rb').read())
            returned_data = pe_att_ext.extract()
            atts = returned_data[0]
            atts['label'] = label
            data.append(atts)
            grouped_ext = returned_data[1]
            if not grouped_data:
              grouped_data = grouped_ext
              continue
            for _library in grouped_ext["libraries"]:
              if not _library in grouped_data["libraries"].keys():
                grouped_data["libraries"].update({_library: grouped_ext["libraries"][_library]})
              else:
                for func in grouped_ext["libraries"][_library]:
                  if not func in grouped_ext["libraries"][_library]:
                    grouped_ext["libraries"][_library].append(func)
            for _export in grouped_ext["exports_list"]:
              if not _export in grouped_data["exports_list"]:
                grouped_data["exports_list"].append(_export)
          except:
            pass
        if return_after_grouping:
          return grouped_data
        return data
    
    def feature_extractor_file(self, input_file):
        if not os.path.exists(input_file):
          print("!!!INPUT FILE (" + input_file + ") NOT FOUND!!!")
          return
        file_data = []
        try:
          pe_att_ext = PEAttributeExtractor(open(input_file,'rb').read())
          atts = pe_att_ext.extract()[0]
          # atts['label'] = label
          file_data.append(atts)
        except:
          pass
        return file_data


class FeatureEstimator():
    def list_files(self, directory):
        file_paths = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_paths.append(os.path.join(root, file))
        return file_paths

    def num_features_estimator(self, given_num_f):
        malware_dir, goodware_dir = args.train[0], args.train[1]
        malware_files = self.list_files(malware_dir)
        goodware_files = self.list_files(goodware_dir)
        feature_space = set()
        feat_ext = FeatureExtractor()

        # for _dir in malware_dirs:
        # input_dir = os.path.join(malware_dir, _dir)
        sampled_malware_files = random.sample(malware_files, train_size)
        data = feat_ext.feature_extractor_dir(sampled_malware_files, 1)
        for _dict in data:
          _dict.pop('label', None)
          for key in _dict:
            value = _dict[key]
            features = value.split()
            for feature in features:
              feature_space.add(feature)

        # for _dir in goodware_dirs:
        #   input_dir = os.path.join(goodware_dir, _dir)
        sampled_goodware_files = random.sample(goodware_files, train_size)
        data = feat_ext.feature_extractor_dir(sampled_goodware_files, 0)
        for _dict in data:
          _dict.pop('label', None)
          for key in _dict:
            value = _dict[key]
            features = value.split()
            for feature in features:
              feature_space.add(feature)
        
        global train_files
        train_files['malware'] = sampled_malware_files
        train_files['goodware'] = sampled_goodware_files

        feature_space = list(feature_space)
        feature_space.sort()
        len_feat_space = len(feature_space)
        obj_len_feat_space = './pipeline/FFNN/saves_model/len_feat_space.obj'
        if not os.path.exists(obj_len_feat_space):
          os.makedirs('./pipeline/FFNN/saves_model/', exist_ok = True)
          with open(obj_len_feat_space, 'wb') as lf_file:
            pickle.dump(len_feat_space, lf_file)
        
        obj_train_files = './pipeline/FFNN/saves_model/train_files.obj'
        if not os.path.exists(obj_train_files):
          os.makedirs('./pipeline/FFNN/saves_model/', exist_ok = True)
          with open(obj_train_files, 'wb') as lf_file:
            pickle.dump(train_files, lf_file)
        num_f = min(given_num_f, len(feature_space)) if given_num_f > 0 else len(feature_space)
        return int(num_f)

class MyModel():
    def __init__(self, apifeature_dims, filename='data.npz'):
        self.apifeature_dims = apifeature_dims
        self.model = self.build_model()
        self.filename = filename
    
    def build_model(self):
        i = Input(shape=(self.apifeature_dims,))
        x = Dense(1024, activation='relu')(i)
        x = Dense(512, activation='relu')(x)
        x = Dense(256, activation='relu')(x)
        x = Dense(128, activation='relu')(x)
        x = Dense(64, activation='relu')(x)
        x = Dense(32, activation='relu')(x)
        x = Dense(1, activation='sigmoid')(x)
        model = Model(i, x)

        return model

    def list_files(self, directory):
        file_paths = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_paths.append(os.path.join(root, file))
        return file_paths

    def load_data(self):
        with open('./pipeline/FFNN/saves_model/train_files.obj', 'rb') as lf_file:
            train_files = pickle.load(lf_file)

        # train_files['goodware'] = train_files['goodware'][:1000]
        # train_files['malware'] = train_files['malware'][:1000]

        # malware_dirs = os.listdir(self.malware_dir)
        # goodware_dirs = os.listdir(self.goodware_dir)
        # malware_files = self.list_files(self.malware_dir)
        # goodware_files = self.list_files(self.goodware_dir)

        feature_space = defaultdict(lambda: 0)
        feat_ext = FeatureExtractor()
        dict_feat_space = {"libraries": {}, "exports_list":[]}
        func_lib_map = {}
        # for _dir in malware_dirs:
        # input_dir = os.path.join(self.malware_dir, _dir)
        # data = feat_ext.feature_extractor_dir(input_dir, 1)
        # grouped_ext = feat_ext.feature_extractor_dir(input_dir, 1, 1)
        sampled_malware_files = train_files['malware']
        data_malware = feat_ext.feature_extractor_dir(sampled_malware_files, 1)
        grouped_ext = feat_ext.feature_extractor_dir(sampled_malware_files, 1, 1)
        if not dict_feat_space:
          dict_feat_space = grouped_ext
        else:
          for _library in grouped_ext["libraries"]:
            if not _library in dict_feat_space["libraries"].keys():
              dict_feat_space["libraries"].update({_library: grouped_ext["libraries"][_library]})
            else:
              for func in grouped_ext["libraries"][_library]:
                if not func in grouped_ext["libraries"][_library]:
                  grouped_ext["libraries"][_library].append(func)
                  func_lib_map[func] = _library
          for _export in grouped_ext["exports_list"]:
            if not _export in dict_feat_space["exports_list"]:
              dict_feat_space["exports_list"].append(_export)
        for _dict in data_malware:
          _dict.pop('label', None)
          for key in _dict:
            value = _dict[key]
            features = value.split()
            for feature in features:
              feature_space[feature] += 1

        # for _dir in goodware_dirs:
        # input_dir = os.path.join(self.goodware_dir, _dir)
        # data = feat_ext.feature_extractor_dir(input_dir, 0)
        # grouped_ext = feat_ext.feature_extractor_dir(input_dir, 0, 1)
        sampled_goodware_files = train_files['goodware']
        data_goodware = feat_ext.feature_extractor_dir(sampled_goodware_files, 0)
        grouped_ext = feat_ext.feature_extractor_dir(sampled_goodware_files, 0, 1)
        if not dict_feat_space:
          dict_feat_space = grouped_ext
        else:
          for _library in grouped_ext["libraries"]:
            if not _library in dict_feat_space["libraries"].keys():
              dict_feat_space["libraries"].update({_library: grouped_ext["libraries"][_library]})
            else:
              for func in grouped_ext["libraries"][_library]:
                if not func in grouped_ext["libraries"][_library]:
                  grouped_ext["libraries"][_library].append(func)
                  func_lib_map[func] = _library
          for _export in grouped_ext["exports_list"]:
            if not _export in dict_feat_space["exports_list"]:
              dict_feat_space["exports_list"].append(_export)
        for _dict in data_goodware:
          _dict.pop('label', None)
          for key in _dict:
            value = _dict[key]
            features = value.split()
            for feature in features:
              feature_space[feature] += 1
        
        feature_space = sorted(feature_space.items(), key=lambda x:x[1])
        feature_space.reverse()
        # feature_space = feature_space[:self.apifeature_dims]
        f_space = set()
        for feature in feature_space[:self.apifeature_dims]:
          if len(f_space) >= self.apifeature_dims:
            break
          if feature[0] in func_lib_map.keys():
            f_space.add(func_lib_map[feature[0]])
          if len(f_space) >= self.apifeature_dims:
            break
          f_space.add(feature[0])

        if len(f_space) != self.apifeature_dims:
          print("!!!NOT POSSIBLE!!!")
          exit(1)

        # feature_space = [i[0] for i in feature_space]
        feature_space = list(f_space)

        xmal, ymal, xben, yben = [], [], [], []
        
        # for _dir in malware_dirs:
        # input_dir = os.path.join(self.malware_dir, _dir)
        # data = feat_ext.feature_extractor_dir(input_dir, 1)
        # sampled_malware_files = train_files['malware']
        # data = feat_ext.feature_extractor_dir(sampled_malware_files, 1)
        for _dict in data_malware:
          ymal.append(1)
          _dict.pop('label', None)
          feature_vector = dict.fromkeys(feature_space, 0)
          for key in _dict:
            value = _dict[key]
            features = value.split()
            for feature in features:
              if feature in feature_space:
                feature_vector[feature] = 1
          values = list(feature_vector.values())    
          xmal.append(values)
        
        # for _dir in goodware_dirs:
        # input_dir = os.path.join(self.goodware_dir, _dir)
        # data = feat_ext.feature_extractor_dir(input_dir, 0)
        # sampled_goodware_files = train_files['goodware']
        # data = feat_ext.feature_extractor_dir(sampled_goodware_files, 0)
        for _dict in data_goodware:
          yben.append(0)
          _dict.pop('label', None)
          feature_vector = dict.fromkeys(feature_space, 0)
          for key in _dict:
            value = _dict[key]
            features = value.split()
            for feature in features:
              if feature in feature_space:
                feature_vector[feature] = 1
          values = list(feature_vector.values())    
          xben.append(values)
        
        obj_dict_fp = './pipeline/FFNN/saves_model/dict_feat.obj'
        os.makedirs('./pipeline/FFNN/saves_model', exist_ok = True)
        with open(obj_dict_fp, 'wb') as df_file:
          pickle.dump(dict_feat_space, df_file)

        obj_fp = './pipeline/FFNN/saves_model/num_features_' + str(self.apifeature_dims) + '/feature_space.obj'
        os.makedirs('./pipeline/FFNN/saves_model/num_features_' + str(self.apifeature_dims), exist_ok = True)
        with open(obj_fp, 'wb') as feature_space_file:
          pickle.dump(feature_space, feature_space_file)

        xmal = np.array(xmal)
        ymal = np.array(ymal)
        xben = np.array(xben)
        yben = np.array(yben)
        np.savez('./pipeline/FFNN/saves_model/num_features_'+str(self.apifeature_dims)+'/'+self.filename, xmal=xmal, ymal=ymal, xben=xben, yben=yben)
        
        print(len(sampled_malware_files))
        print(len(sampled_goodware_files))

        return (xmal, ymal), (xben, yben)
    
    def train(self, epochs, batch_size=32, is_first=1):
        (xmal, ymal), (xben, yben) = self.load_data()
        xtrain_mal, xtest_mal, ytrain_mal, ytest_mal = train_test_split(xmal, ymal, test_size=0.20)
        xtrain_ben, xtest_ben, ytrain_ben, ytest_ben = train_test_split(xben, yben, test_size=0.20)
        x_train = np.concatenate((xtrain_mal, xtrain_ben))
        y_train = np.concatenate((ytrain_mal, ytrain_ben))
        x_test = np.concatenate((xtest_mal, xtest_ben))
        y_test = np.concatenate((ytest_mal, ytest_ben))
        self.model.compile(optimizer='adam',
              loss='binary_crossentropy',
              metrics=['accuracy'])
        steps_per_epoch = x_train.shape[0] // batch_size
        model_checkpoint_callback = callbacks.ModelCheckpoint(
            filepath='./pipeline/FFNN/saves_model/num_features_' + str(self.apifeature_dims) + '/best_model.h5',
            save_best_only=True,
            monitor='val_accuracy',
            mode='max',
            verbose=1
        )
        self.model.fit(x_train, y_train, validation_data=(x_test, y_test), steps_per_epoch=steps_per_epoch, epochs=epochs, callbacks=[model_checkpoint_callback])
        self.model.save('./pipeline/FFNN/saves_model/num_features_' + str(self.apifeature_dims) + '/final_model.h5')
# if __name__ == '__main__':
#     if args.train:
#       feat_estm = FeatureEstimator()
#       num_f = feat_estm.num_features_estimator(int(args.train[2]))
#       model = MyModel(apifeature_dims=int(num_f))
#       model.train(epochs=100, batch_size=64)
#     elif args.test:
#       with open('./pipeline/FFNN/saves_model/len_feat_space.obj', 'rb') as lf_file:
#         len_feat_space = pickle.load(lf_file)
#       num_f = min(int(args.test[1]), len_feat_space) if int(args.test[1]) > 0 else len_feat_space
#       model_file = './pipeline/FFNN/saves_model/num_features_' + str(num_f) + '/best_model.h5'
#       if os.path.exists(model_file):
#         model = load_model(model_file)
#         feature_space_path = './pipeline/FFNN/saves_model/num_features_' + str(num_f) + '/feature_space.obj'
#         if os.path.exists(feature_space_path):
#           with open(feature_space_path, 'rb') as feature_space_file:
#             feature_space = pickle.load(feature_space_file)
#         else:
#           print('!!!LOADABLE FEATURE SPACE FILE NOT FOUND!!!')
#           exit(0)
        
#         if os.path.exists('./pipeline/FFNN/saves_model/dict_feat.obj'):
#           with open('./pipeline/FFNN/saves_model/dict_feat.obj', 'rb') as df_file:
#             dict_feat_space = pickle.load(df_file)
#         else:
#           print('!!!LOADABLE DICT FEATURE SPACE FILE NOT FOUND!!!')
#           exit(0)
#       else:
#         print('!!!MODEL TO BE TESTED DOES NOT EXIST!!!')
#         exit(0)
      
#       input_file = args.test[0]
#       x_test = []
#       feat_ext = FeatureExtractor()
#       data = feat_ext.feature_extractor_file(input_file)
#       for _dict in data:
#         feature_vector = dict.fromkeys(feature_space, 0)
#         for key in _dict:
#           value = _dict[key]
#           features = value.split()
#           for feature in features:
#             if feature in feature_space:
#               feature_vector[feature] = 1
#         values = list(feature_vector.values())    
#         x_test.append(values)
      
#       x_test = np.asarray(x_test)
#       y_pred = model.predict(x_test)
#       y_pred = int(y_pred[0][0]>0.5)
#       # print(y_pred)
#       if y_pred == 1:
#         print(f"\nTest Sample Result: {y_pred} (Malware)\n")
#       else:
#         print(f"\nTest Sample Result: {y_pred} (Goodware)\n")


class Model:
  def __init__(self):
        num_f = 1500
        model_file = 'pipeline/FFNN/saves_model/num_features_' + str(num_f) + '/best_model.h5'
        if os.path.exists(model_file):
          self.model = load_model(model_file)
          feature_space_path = 'pipeline/FFNN/saves_model/num_features_' + str(num_f) + '/feature_space.obj'
          if os.path.exists(feature_space_path):
            with open(feature_space_path, 'rb') as feature_space_file:
              self.feature_space = pickle.load(feature_space_file)
          else:
            print('!!!LOADABLE FEATURE SPACE FILE NOT FOUND!!!')
            exit(0)
          
          # if os.path.exists('pipeline/FFNN/saves_model/dict_feat.obj'):
          #   with open('pipeline/FFNN/saves_model/dict_feat.obj', 'rb') as df_file:
          #     dict_feat_space = pickle.load(df_file)
          # else:
          #   print('!!!LOADABLE DICT FEATURE SPACE FILE NOT FOUND!!!')
          #   exit(0)
        else:
          print('!!!MODEL TO BE TESTED DOES NOT EXIST!!!')
          exit(0)

  def predict_threshold(self, bytez, threshold=0.8):
      # pe_att_ext = PEAttributeExtractor(bytez)
      # extracted_attributes = pe_att_ext.extract()
      # test_data = [extracted_attributes]
      # test_data = pd.DataFrame(test_data)
      # test_data = test_data[(test_data["label"] == 1) | (test_data["label"] == 0)]
      # y_pred = self.clf.predict_threshold(test_data, threshold)[0]

      # with open('pipeline/FFNN/saves_model/len_feat_space.obj', 'rb') as lf_file:
      #   len_feat_space = pickle.load(lf_file)
      
      
      # with open('temp.dll', 'wb') as f:
      #       f.write(bytez)
      input_file = 'temp.dll'
      x_test = []
      feat_ext = FeatureExtractor()
      data = feat_ext.feature_extractor_file(input_file)
      for _dict in data:
        feature_vector = dict.fromkeys(self.feature_space, 0)
        for key in _dict:
          value = _dict[key]
          features = value.split()
          for feature in features:
            if feature in self.feature_space:
              feature_vector[feature] = 1
        values = list(feature_vector.values())    
        x_test.append(values)
      
      x_test = np.asarray(x_test)
      y_pred = self.model.predict(x_test)
      # y_pred = int(y_pred[0][0]>=.5)
      y_pred = y_pred[0][0]
      print(y_pred)
      if y_pred >= 0.5:
        print(f"\nFFNN Test Sample Result: {y_pred} (Malware)\n")
      else:
        print(f"\nFFNN Test Sample Result: {y_pred} (Goodware)\n")

      return y_pred
      