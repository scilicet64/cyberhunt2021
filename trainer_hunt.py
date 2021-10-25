# -*- coding: utf-8 -*-
"""
Created on Sat Nov  3 11:25:28 2018

@author: Sowmya
"""

import datagenerator_hunt as datagenerator
import modelgenerator_hunt as modelgenerator
from datetime import datetime
import math
import pathlib
import hashlib
import json
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score


import matplotlib.pyplot as plt
import tensorflow as tf
import os
import numpy as np
from sklearn.metrics import roc_curve, auc
import pandas as pd



def getID():
    global modelConfig
    if not "resultDir" in modelConfig:
        modelConfig["resultDir"]="*"
    configString = str(modelConfig)
    configString= configString.replace(modelConfig["resultDir"],"*")
    return hashlib.md5(configString.encode("UTF-8")).hexdigest()


os.environ["PATH"] += os.pathsep + 'C:/Program Files/Graphviz/bin/'
# Specify which GPU(s) to use
#os.environ["CUDA_VISIBLE_DEVICES"] = "1"  # Or 2, 3, etc. other than 0
# On CPU/GPU placement
config = tf.compat.v1.ConfigProto(allow_soft_placement=True, log_device_placement=True)
config.gpu_options.allow_growth = True
tf.compat.v1.Session(config=config)

#dataset_train = datagenerator.loadDataset("../datasetEvaluation/attackFilesExtractor/CIC-IDS-2017/Monday-WorkingHours.pcap_ISCX_Cleaned.csv")
datasetType = 'hunt2021'
_trainingFile = 'data/testfiles/custom_normal_public.csv'
_mainresultDir = 'results/'
testfiles = ["custom_reconnaissance","custom_sqli","custom_portscan","custom_xss","custom_bruteforce","custom_dataexf","custom_foothold","custom_lateralmovement"]


if not pathlib.Path(_mainresultDir).exists():
    os.mkdir(_mainresultDir)
overviewfile = "overview/overview_results.csv"
if not pathlib.Path("overview").exists():
    os.mkdir("overview")



_nTimesteps = 3
_epochs = 100
_batchsize = 20

dontshow=["Validation_X","X_train"]
modelnames = modelgenerator.getAvailableModels()
print("Available Models:", modelnames)
for modelname in modelnames.keys():
    sequences = modelnames[modelname]
    for useSequence in sequences:
        for usePayload in [False,True,"percentage"]:
            for useFeatureScaling in [True,False]:
                dt_string = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                tf.keras.backend.clear_session()
                modelConfig = dict()
                modelConfig["_epochs"] = _epochs
                modelConfig["_batchsize"] = _batchsize
                modelConfig["modelname"] = modelname
                modelConfig["dataDescription"] = datasetType + "_model"
                modelConfig["datasetType"] = datasetType
                modelConfig["nTimesteps"] = _nTimesteps
                modelConfig["useCache"] = True
                modelConfig["usePayload"] = usePayload
                modelConfig["useSequence"] = useSequence
                modelConfig["useFeatureScaling"] = useFeatureScaling
                modelConfig["trainingFile"]=_trainingFile

                configJson = json.dumps(modelConfig)
                print("using modelConfig:", str(modelConfig))
                print("Loading Training dataset:", _trainingFile)
                dataset_train = datagenerator.loadDataset(_trainingFile, modelConfig["useSequence"])
                _nTotal = dataset_train.shape[0]
                _nColumns = dataset_train.shape[1]
                # Using 75% of the data for training and remaining 25% for validation testing
                _nSamplesTrain = math.ceil(_nTotal * 0.75)
                _nSamplesValidation = _nTotal - _nSamplesTrain

                modelConfig["X_train"] = datagenerator.getInput(datasetType, dataset_train, 0, _nSamplesTrain, _nColumns,
                                                                modelConfig["usePayload"])
                modelConfig["Validation_X"] = datagenerator.getInput(datasetType, dataset_train, _nSamplesTrain,
                                                                     _nSamplesTrain + _nSamplesValidation, _nColumns,
                                                                     modelConfig["usePayload"])
                modelConfig["nOperatingColumns"] = len(modelConfig["X_train"][0])

                #Converting training inputs into LSTM training inputs
                sc = MinMaxScaler(feature_range=(0, 1))
                if modelConfig["useFeatureScaling"]:
                    # Feature Scaling -Normalization recommended for RNN
                    modelConfig["X_train"] = sc.fit_transform(modelConfig["X_train"])
                    modelConfig["Validation_X"] = sc.fit_transform(modelConfig["Validation_X"])
                else:
                    modelConfig["X_train"] = modelConfig["X_train"].astype('float32')
                    modelConfig["Validation_X"] = modelConfig["Validation_X"].astype('float32')

                if modelConfig["useSequence"] is not False :
                    modelConfig["X_train_sequence"] = datagenerator.getInputSequence(modelConfig["X_train"], _nTimesteps, modelConfig["nOperatingColumns"])
                    modelConfig["Validation_X_sequence"] = datagenerator.getInputSequence(modelConfig["Validation_X"], _nTimesteps, modelConfig["nOperatingColumns"])

                id = getID()
                if pathlib.Path(overviewfile).exists():
                    resultsdf = pd.read_csv(overviewfile, header=0, encoding="ISO-8859-1")
                    if resultsdf is not None:
                        foundtests = resultsdf[resultsdf["id"] == id]["testname"]
                        if len(foundtests) > 0:
                            diff = set(testfiles).difference(set(foundtests.to_list()))
                            if len(diff)==0:
                                print("Found results for all tests, skipping...")
                                continue

                modelConfig["resultDir"] = _mainresultDir + id + "/"
                if not pathlib.Path(modelConfig["resultDir"]).exists():
                    os.mkdir(modelConfig["resultDir"])

                model = modelgenerator.get(modelConfig)

                if not pathlib.Path(modelConfig["resultDir"]).exists():
                    os.mkdir(modelConfig["resultDir"])

                with open(modelConfig["resultDir"] + "model.json","w") as dump:
                    dump.write(configJson)

                model = modelgenerator.fit(model,modelConfig,id)

                for testfile in testfiles:
                    modelConfig["testname"]= testfile
                    if pathlib.Path(overviewfile).exists():
                        resultsdf = pd.read_csv(overviewfile, header=0, encoding="ISO-8859-1")
                        if resultsdf is not None:
                            foundtest = resultsdf[(resultsdf["id"] == id)&(resultsdf["testname"] == modelConfig["testname"])]
                            if len(foundtest)>0:
                                continue

                    testDatasetFile = "data/testfiles/" + testfile + ".csv"
                    print(testDatasetFile)
                    dataset_test = datagenerator.loadDataset(testDatasetFile,modelConfig["useSequence"])
                    checklabels = len(dataset_test.groupby(["Activity", "Stage"]).size())
                    if checklabels<2:
                        print("Skipping meaningless test, no malicious labels",testDatasetFile)
                        continue

                    _nSamplesPred = dataset_test.shape[0]
                    _nColumns = dataset_test.shape[1]

                    modelConfig["X_test"] = datagenerator.getInput(datasetType, dataset_test, 0, _nSamplesPred, _nColumns,modelConfig["usePayload"])

                    sc_pred = MinMaxScaler(feature_range=(0, 1))
                    if modelConfig["useFeatureScaling"]:
                        print("Scaling test data...")
                        # Feature Scaling -Normalization recommended for RNN
                        modelConfig["X_test"] = sc_pred.fit_transform(modelConfig["X_test"]) # will also be input for sequence
                    else:
                        modelConfig["X_test"] = modelConfig["X_test"].astype('float32')

                    if (modelConfig["useSequence"] is not False):
                        removeRows = _nTimesteps
                        modelConfig["X_test_sequence"] = datagenerator.getInputSequence(modelConfig["X_test"], _nTimesteps,
                                                                                        _nColumns)
                    else:
                        removeRows=0
                    y_test,y_test_boolean = datagenerator.getLabelColumn(datasetType, dataset_test, 0, _nSamplesPred-removeRows)




                    print("Predicting...")
                    predictionsDir = modelConfig["resultDir"] + "predictions/"
                    if not pathlib.Path(predictionsDir).exists():
                        os.mkdir(predictionsDir)


                    modelConfig["y_test"] = y_test
                    prediction_input,prediction_result,rmse,decisions,roc_auc,pr_auc = modelgenerator.predict(model, modelConfig)
                    print("Area Under Curve score ROC",roc_auc)
                    print("Area Under Curve score PR", pr_auc)

                    resultColumns = ["id","modelname", "trainingFile", "testname","timestamp", "useFeatureScaling", "usePayload","sorted", "nTimesteps","epochs","batchsize","roc_auc","pr_auc"]

                    if type(modelConfig["useSequence"])==bool:
                        sorted = False
                    else:
                        sorted=modelConfig["useSequence"]
                    result = [id,modelConfig["modelname"],modelConfig["trainingFile"], modelConfig["testname"], dt_string, modelConfig["useFeatureScaling"], modelConfig["usePayload"], sorted, modelConfig["nTimesteps"],
                        modelConfig["_epochs"], modelConfig["_batchsize"],roc_auc,pr_auc]


                    for index,y_pred in enumerate(decisions):
                        acc = accuracy_score(y_test_boolean, y_pred)
                        pre = precision_score(y_test_boolean, y_pred)
                        rec = recall_score(y_test_boolean, y_pred)
                        f1_sc = f1_score(y_test_boolean, y_pred)
                        decisionname = modelgenerator.getDecisionName(index)
                        print("accuracy_score " , decisionname, acc)
                        print("precision_score " , decisionname, pre)
                        print("recall_score ", decisionname, rec)
                        print("f1_score" , decisionname, f1_sc)
                        resultColumns = resultColumns + ["acc_"+decisionname,"pre_"+decisionname,"rec_"+decisionname,"f1_score_"+decisionname]
                        result = result + [acc, pre, rec, f1_sc]


                    if pathlib.Path(overviewfile).exists():
                        resultsdf = pd.read_csv(overviewfile, header=0, encoding="ISO-8859-1")
                        result = resultsdf.values.tolist() + [result]
                        resultsdf = pd.DataFrame(result, columns=resultColumns)
                    else:
                        resultsdf = pd.DataFrame([result], columns=resultColumns)
                    resultsdf.to_csv(overviewfile, sep=",", decimal=".", index=False)



