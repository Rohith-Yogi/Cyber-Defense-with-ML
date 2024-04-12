import re
import lief
import math
import os
import sys
import gzip
import pandas as pd
import _pickle as cPickle
from scipy import sparse
from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer, HashingVectorizer
from sklearn.preprocessing import MinMaxScaler, MaxAbsScaler
from sklearn.ensemble import RandomForestClassifier
from copy import deepcopy
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import f_classif


class PEAttributeExtractor:
    libraries = ""
    functions = ""
    exports = ""

    # initialize extractor
    def __init__(self, bytez):
        # save bytes
        self.bytez = bytez
        # save pe
        # self.pe = pefile.PE(data=bytez, fast_load=True)
        # parse using lief
        self.lief_binary = lief.PE.parse(list(bytez))
        # attributes
        self.attributes = {}

    # extract string metadata
    def extract_string_metadata(self):
        # occurances of the string 'C:\'.  Not actually extracting the path
        paths = re.compile(b'c:\\\\', re.IGNORECASE)
        # occurances of http:// or https://.  Not actually extracting the URLs
        urls = re.compile(b'https?://', re.IGNORECASE)
        # occurances of the string prefix HKEY_.  No actually extracting registry names
        registry = re.compile(b'HKEY_')
        # crude evidence of an MZ header (dropper?) somewhere in the byte stream
        mz = re.compile(b'MZ')
        return {
            'string_paths': len(paths.findall(self.bytez)),
            'string_urls': len(urls.findall(self.bytez)),
            'string_registry': len(registry.findall(self.bytez)),
            'string_MZ': len(mz.findall(self.bytez))
        }

    # extract entropy
    def extract_entropy(self):
        if not self.bytez:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(self.bytez.count(bytes(x))) / len(self.bytez)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    # extract identify
    def extract_identify(self):
        # Load PE Signature Database & Sample PE
        # db_path = os.path.dirname(__file__) + "defender/models/peid_userdb_uft8.txt"
        # sigs=peutils.SignatureDatabase(db_path) #data=open(db_path, 'r').read())
        # # Match PE against signature database
        # matches=sigs.match_all(self.pe, ep_only=True)
        # m = []
        # if matches:
        #     for l in matches:
        #         for i in l:
        #             m.append(str(i))
        #     return " ".join(m)
        # else:
        return ""

    # extract attributes
    def extract(self):

        try:
            has_signature = int(self.lief_binary.has_signature)
        except:
            has_signature = 0

        # get general info
        self.attributes.update({
            "size": len(self.bytez),
            # EMBER only
            "virtual_size": self.lief_binary.virtual_size,
            # EMBER only
            "has_debug": int(self.lief_binary.has_debug),
            # EMBER only
            "imports": len(self.lief_binary.imports),
            # EMBER only
            "exports": len(self.lief_binary.exported_functions),
            # EMBER only
            "has_relocations": int(self.lief_binary.has_relocations),
            # EMBER only
            "has_resources": int(self.lief_binary.has_resources),
            # EMBER only
            "has_signature": has_signature,
            # EMBER only
            "has_tls": int(self.lief_binary.has_tls),
            # EMBER only
            "symbols": len(self.lief_binary.symbols),
        })

        # get header info
        self.attributes.update({
            "timestamp": self.lief_binary.header.time_date_stamps,
            # TODO: do we transform MACHINE into categorical feature instead of int?
            "machine": str(self.lief_binary.header.machine),
            # TODO: NFS only
            "numberof_sections": self.lief_binary.header.numberof_sections,
            # TODO: NFS only
            # "numberof_symbols": self.lief_binary.header.numberof_symbols,
            # TODO: NFS only
            # "pointerto_symbol_table": self.lief_binary.header.pointerto_symbol_table,
            # TODO: NFS only
            # "sizeof_optional_header": self.lief_binary.header.sizeof_optional_header,
            # TODO: NFS only
            # "characteristics": int(self.lief_binary.header.characteristics),
            "characteristics_list": " ".join(
                [str(c).replace("HEADER_CHARACTERISTICS.", "") for c in self.lief_binary.header.characteristics_list])
        })

        try:
            baseof_data = self.lief_binary.optional_header.baseof_data
        except:
            baseof_data = 0

        # get optional header
        self.attributes.update({
            # TODO: NFS only
            # "baseof_code": self.lief_binary.optional_header.baseof_code,
            # TODO: NFS only
            # "baseof_data": baseof_data,
            # TODO: Ember uses a dll_characteristics list
            # "dll_characteristics": self.lief_binary.optional_header.dll_characteristics,
            "dll_characteristics_list": " ".join([str(d).replace("DLL_CHARACTERISTICS.", "") for d in
                                                  self.lief_binary.optional_header.dll_characteristics_lists]),
            # TODO: NFS only
            # "file_alignment": self.lief_binary.optional_header.file_alignment,
            # TODO: NFS only
            # "imagebase": self.lief_binary.optional_header.imagebase,
            "magic": str(self.lief_binary.optional_header.magic).replace("PE_TYPE.", ""),
            # TODO: NFS only - using pefile
            # "PE_TYPE": self.pe.PE_TYPE,
            # "PE_TYPE": int(self.lief_binary.optional_header.magic),
            # EMBER only
            "major_image_version": self.lief_binary.optional_header.major_image_version,
            # EMBER only
            "minor_image_version": self.lief_binary.optional_header.minor_image_version,
            # EMBER only
            "major_linker_version": self.lief_binary.optional_header.major_linker_version,
            # EMBER only
            "minor_linker_version": self.lief_binary.optional_header.minor_linker_version,
            # EMBER only
            "major_operating_system_version": self.lief_binary.optional_header.major_operating_system_version,
            # EMBER only
            "minor_operating_system_version": self.lief_binary.optional_header.minor_operating_system_version,
            # EMBER only
            "major_subsystem_version": self.lief_binary.optional_header.major_subsystem_version,
            # EMBER only
            "minor_subsystem_version": self.lief_binary.optional_header.minor_subsystem_version,
            # TODO: NFS only
            # "numberof_rva_and_size": self.lief_binary.optional_header.numberof_rva_and_size,
            "sizeof_code": self.lief_binary.optional_header.sizeof_code,
            "sizeof_headers": self.lief_binary.optional_header.sizeof_headers,
            # EMBER only
            "sizeof_heap_commit": self.lief_binary.optional_header.sizeof_heap_commit,
            # TODO: NFS only
            # "sizeof_image": self.lief_binary.optional_header.sizeof_image,
            # TODO: NFS only
            # "sizeof_initialized_data": self.lief_binary.optional_header.sizeof_initialized_data,
            # TODO: NFS only
            # "sizeof_uninitialized_data": self.lief_binary.optional_header.sizeof_uninitialized_data,
            # EMBER only
            # "subsystem": str(self.lief_binary.optional_header.subsystem).replace("SUBSYSTEM.","")
        })

        # get entropy
        self.attributes.update({
            # TODO: NFS only
            # "entropy": self.extract_entropy()
        })

        # get string metadata
        # EMBER only
        self.attributes.update(self.extract_string_metadata())

        # get imported libraries and functions
        if self.lief_binary.has_imports:
            self.libraries = " ".join([l for l in self.lief_binary.libraries])
            self.libraries = " {} ".format(self.libraries)
            self.functions = " ".join([f.name for f in self.lief_binary.imported_functions])
            self.functions = " {} ".format(self.functions)
        self.attributes.update({"functions": self.functions, "libraries": self.libraries})

        # get exports
        if self.lief_binary.has_exports:
            self.exports = " ".join([f.name for f in self.lief_binary.exported_functions])
        self.attributes.update({"exports_list": self.exports})

        # get identify
        # self.attributes.update({"identify": self.extract_identify()})

        # label = 1 malware, 0, goodware
        self.attributes.update({"label": 1})

        return (self.attributes)


# need for speed class
class NeedForSpeedModel():
    # numerical attributes
    NUMERICAL_ATTRIBUTES = [
        # 'string_paths', 'string_urls', 'string_registry', 'string_MZ', 'size',
        'virtual_size', 'has_debug', 'imports', 'exports', 'has_relocations',
        'has_resources', 'has_signature', 'has_tls', 'symbols', 'timestamp',
        'numberof_sections', 'major_image_version', 'minor_image_version',
        'major_linker_version', 'minor_linker_version', 'major_operating_system_version',
        'minor_operating_system_version', 'major_subsystem_version',
        'minor_subsystem_version', 'sizeof_code', 'sizeof_headers', 'sizeof_heap_commit'
    ]

    # categorical attributes
    CATEGORICAL_ATTRIBUTES = [
        'machine', 'magic'
    ]

    # textual attributes
    TEXTUAL_ATTRIBUTES = ['libraries', 'functions', 'exports_list',
                          'dll_characteristics_list', 'characteristics_list']

    # 'dll_characteristics_list' and 'characteristics_list' are texts or multi-categoricals??

    # label
    LABEL = "label"

    # initialize NFS classifier
    def __init__(self,
                 categorical_extractor=OneHotEncoder(handle_unknown="ignore"),
                 # textual_extractor = TfidfVectorizer(max_features=500, token_pattern=r"(?<=\s)(.*?)(?=\s)"),
                 textual_extractor=HashingVectorizer(n_features=50000, token_pattern=r"(?<=\s)(.*?)(?=\s)"),
                 # feature_scaler = MinMaxScaler(),
                 feature_scaler=MaxAbsScaler(),
                 classifier=RandomForestClassifier()):
        self.base_categorical_extractor = categorical_extractor
        self.base_textual_extractor = textual_extractor
        self.base_feature_scaler = feature_scaler
        self.base_classifier = classifier
        self.transformer = None

    # append features to original features list
    def _append_features(self, original_features, appended):
        if original_features:
            for l1, l2 in zip(original_features, appended):
                for i in l2:
                    l1.append(i)
            return (original_features)
        else:
            return appended.tolist()

    # train a categorical extractor
    def _train_categorical_extractor(self, categorical_attributes):
        # initialize categorical extractor
        self.categorical_extractor = deepcopy(self.base_categorical_extractor)
        # train categorical extractor
        self.categorical_extractor.fit(categorical_attributes.values)

    # transform categorical attributes into features
    def _transform_categorical_attributes(self, categorical_attributes):
        # transform categorical attributes using categorical extractor
        cat_features = self.categorical_extractor.transform(categorical_attributes.values)
        # return categorical features
        return cat_features

    # train a textual extractor
    def _train_textual_extractor(self, textual_attributes):
        # initialize textual extractors
        self.textual_extractors = {}
        # train feature extractor for each textual attribute
        for att in self.TEXTUAL_ATTRIBUTES:
            # initialize textual extractors
            self.textual_extractors[att] = deepcopy(self.base_textual_extractor)
            # train textual extractor
            self.textual_extractors[att].fit(textual_attributes[att].values)

    # transform textual extractor
    def _transform_textual_attributes(self, textual_attributes):
        # initialize features
        textual_features = None
        # extract features from each textual attribute
        for att in self.TEXTUAL_ATTRIBUTES:
            # train textual extractor
            att_features = self.textual_extractors[att].transform(textual_attributes[att].values)
            # transform into array (when it is an sparse matrix)
            # att_features = att_features.toarray()
            if textual_features == None:
                textual_features = att_features
            else:
                # append textual features
                textual_features = sparse.hstack((textual_features, att_features))
            # append textual features
            # textual_features = self._append_features(textual_features, att_features)
        return textual_features

    # train feature scaler
    def _train_feature_scaler(self, features):
        # initialize feature scaler
        self.feature_scaler = deepcopy(self.base_feature_scaler)
        # train feature scaler
        self.feature_scaler.fit(features)

    # transform features using feature scaler
    def _transform_feature_scaler(self, features):
        return self.feature_scaler.transform(features)

    # train classifier
    def _train_classifier(self, features, labels):
        # initialize classifier
        self.classifier = deepcopy(self.base_classifier)
        # train feature scaler
        self.classifier.fit(features, labels)

    # fit classifier using raw input
    def fit(self, train_data, n_features=0):
        # get labels
        train_labels = train_data[self.LABEL]
        # delete label column
        del train_data[self.LABEL]
        # initialize train_features with numerical ones
        train_features = sparse.csr_matrix(train_data[self.NUMERICAL_ATTRIBUTES].values)

        # print("Training categorical features...", flush=True)
        # train categorical extractor
        self._train_categorical_extractor(train_data[self.CATEGORICAL_ATTRIBUTES])
        # transform categorical data
        cat_train_features = self._transform_categorical_attributes(train_data[self.CATEGORICAL_ATTRIBUTES])
        # append categorical_features to train_features
        # train_features = self._append_features(train_features, cat_train_features)
        train_features = sparse.hstack((train_features, cat_train_features))

        # print("Training textual features...", flush=True)
        # train textual extractor (ALL DATA)
        self._train_textual_extractor(train_data[self.TEXTUAL_ATTRIBUTES])
        # train textual extractor (MALWARE ONLY)
        # self._train_textual_extractor(train_data[train_labels == 1][self.TEXTUAL_ATTRIBUTES])
        # transform textual data
        tex_train_features = self._transform_textual_attributes(train_data[self.TEXTUAL_ATTRIBUTES])
        # append textual_features to train_features
        # train_features = self._append_features(train_features, tex_train_features)
        train_features = sparse.hstack((train_features, tex_train_features))
        # transform in sparse matrix
        # train_features = csr_matrix(train_features)

        # print("Normalizing features...", flush=True)
        # train feature normalizer
        self._train_feature_scaler(train_features)
        # transform features
        train_features = self._transform_feature_scaler(train_features)

        # print("Training classifier...", flush=True)
        # train classifier
        if n_features == 0:
            return self._train_classifier(train_features, train_labels)
        else:
            self.transformer = SelectKBest(f_classif, k=n_features)
            X_new = self.transformer.fit_transform(train_features, train_labels)
            return self._train_classifier(X_new, train_labels)

    def _extract_features(self, data):
        # initialize features with numerical ones
        # features = data[self.NUMERICAL_ATTRIBUTES].values.tolist()
        features = sparse.csr_matrix(data[self.NUMERICAL_ATTRIBUTES].values)

        # print("Getting categorical features...", flush=True)
        # transform categorical data
        cat_features = self._transform_categorical_attributes(data[self.CATEGORICAL_ATTRIBUTES])
        # append categorical_features to features
        # features = self._append_features(features, cat_features)
        features = sparse.hstack((features, cat_features))

        # print("Getting textual features...", flush=True)
        # transform textual data
        tex_features = self._transform_textual_attributes(data[self.TEXTUAL_ATTRIBUTES])
        # append textual_features to features
        # features = self._append_features(features, tex_features)
        features = sparse.hstack((features, tex_features))
        # transform in sparse matrix
        # features = csr_matrix(features)

        # print("Normalizing features...", flush=True)
        # transform features
        features = self._transform_feature_scaler(features)

        # return features
        return (features)

    def predict(self, test_data):
        # extract features
        if self.transformer is None:
            test_features = self._extract_features(test_data)
        else:
            test_features = self.transformer.transform(self._extract_features(test_data))
        # print("Predicting classes...", flush=True)
        # predict features
        return self.classifier.predict(test_features)

    def predict_proba(self, test_data):
        # extract features
        test_features = self._extract_features(test_data)
        # if self.transformer is None:
        #     test_features = self._extract_features(test_data)
        # else:
        #     test_features = self.transformer.transform(self._extract_features(test_data))

        # print("Predicting classes (proba)...", flush=True)
        # predict features
        return self.classifier.predict_proba(test_features)

    def predict_threshold(self, test_data, threshold=0.75):
        # extract features
        test_features = self._extract_features(test_data)

        print("Predicting classes (threshold = {})...".format(threshold), flush=True)
        # predict features
        prob = self.classifier.predict_proba(test_features)
        # initialize pred
        pred = []
        # iterate over probabilities
        for p in prob:
            # add prediction
            pred.append(int(p[0] < threshold))
        # return prediction
        return pred


def load_gzip_pickle(filename):
    fp = gzip.open(filename, 'rb')
    obj = cPickle.load(fp)
    fp.close()
    return obj


def NFS_predict(file):
    clf = load_gzip_pickle("nfs/NFS_21_ALL_hash_50000_WITH_MLSEC20.pkl")
    pe_att_ext = PEAttributeExtractor(open(file, 'rb').read())
    extracted_attributes = pe_att_ext.extract()
    test_data = [extracted_attributes]
    test_data = pd.DataFrame(test_data)
    test_data = test_data[(test_data["label"] == 1) | (test_data["label"] == 0)]
    y_pred = clf.predict_threshold(test_data, 0.5)[0]
    return y_pred


class Model:
    def __init__(self):
        pkl_path = os.path.join(os.getenv("ASSETS_PATH", "assets"), "NFS_21_ALL_hash_50000_WITH_MLSEC20.pkl")
        print("model path:", pkl_path)

        self.clf = load_gzip_pickle(pkl_path)   # local
        # self.clf = load_gzip_pickle("defender/nfs/NFS_21_ALL_hash_50000_WITH_MLSEC20.pkl")   # within the container

    def predict_threshold(self, bytez, threshold=0.8):
        pe_att_ext = PEAttributeExtractor(bytez)
        extracted_attributes = pe_att_ext.extract()
        test_data = [extracted_attributes]
        test_data = pd.DataFrame(test_data)
        test_data = test_data[(test_data["label"] == 1) | (test_data["label"] == 0)]
        # y_pred = self.clf.predict_threshold(test_data, threshold)[0]
        y_pred = self.clf.predict_proba(test_data)
        y_pred = y_pred[0][1]
        print("NFS : ")
        print(y_pred)
        return y_pred