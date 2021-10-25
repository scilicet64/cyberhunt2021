# -*- coding: utf-8 -*-
"""
Created on Sat Nov  3 11:11:04 2018

@author: Sowmya
"""

from tensorflow.python.keras.layers import Input, LSTM, RepeatVector, Dense
#regularizers
from tensorflow.python.keras.models import Model
from tensorflow.python.keras.utils.vis_utils import plot_model
from tensorflow.python.keras.models import Model, model_from_json
from tensorflow.python.keras.callbacks import ModelCheckpoint, EarlyStopping
from numpy.testing import assert_allclose
from tensorflow.python.keras.models import load_model
from sklearn import svm
import numpy as np
import pandas as pd
import math
import matplotlib.pyplot as plt
import os
import pathlib
from sklearn.metrics import roc_curve, auc, precision_recall_curve

def getAvailableModels():
    return dict( [("SAE" , [False]), ("SAE_LSTM" , [True,"sortedDstPort"]), ("ocSVM" , [False])] ) #with useSequence variable True/False

def fit( model, config,id):
    global _model_ocSVM
    if (config["modelname"]=="ocSVM"):
        return model.fit(config["X_train"] )
    elif (config["modelname"]=="SAE") or (config["modelname"]=="SAE_LSTM"):
        checkpointFile = "../aitd/checkpoint_"+id+".h5"
        storeFile = "../aitd/model_" + config["modelname"] + "_" + id + ".h5"
        if (("useCache" in config) and (config["useCache"]) and os.path.isfile(storeFile)):
            print("Loading model from cache")
            model = load_model(storeFile)
            return model

        checkpoint = ModelCheckpoint(checkpointFile, monitor='loss', verbose=1, save_best_only=True, mode='min')
        #earlyStopping = EarlyStopping(monitor='val_loss', mode='min', verbose=1, patience=3)
        #callbacks_list = [checkpoint, earlyStopping]
        callbacks_list = [checkpoint]
        #Training autoencoder
        valX = config["Validation_X"]
        trainX= config["X_train"]
        if config["useSequence"] is not False:
            valX = config["Validation_X_sequence"]
            trainX = config["X_train_sequence"]
        else:
            valX = config["Validation_X"]
            trainX = config["X_train"]
        model_history = model.fit(trainX,trainX,
                                  epochs=config["_epochs"],
                                  batch_size=config["_batchsize"],
                                  shuffle=False,
                                  validation_data=(valX,
                                      valX),
                                  callbacks=callbacks_list)
        print("Done fitting")
        # Save the model and serialize model to JSON and h5
        model.save(storeFile)
        print("Saved model to disk")


        loss = model_history.history['loss']
        val_loss = model_history.history['val_loss']
        epochs = range(config["_epochs"])
        plt.figure()
        plt.plot(epochs, loss, color='red', label='Training loss')
        plt.plot(epochs, val_loss, color='blue', label='Validation loss')
        plt.title('Training and Validation loss ' + config["modelname"])
        plt.xlabel('epochs')
        plt.ylabel('loss')
        plt.legend()
        plt.savefig(config["resultDir"]+'LossColored_' + config["modelname"] + '.png')
        plt.show()
    else:
        raise Exception("Failed: fit modelname" + config["modelname"] + " not existing")
    return model

def get( config):
    if config["modelname"]=="ocSVM":
        model=get_ocSVM(config)
    elif config["modelname"]=="SAE":
        model=getSAE(config)
    elif config["modelname"]=="SAE_LSTM":
        if config["nTimesteps"]==0:
            raise Exception("config[\"nTimesteps\"]==0")
        model=getSAE_LSTM(config)
    else:
        raise Exception("Failed: get modelname " + config["modelname"] + " not existing")
    if hasattr(model,"layers"):
        print("plotting model to file")
        plot_model(model, to_file=config["resultDir"] + config["modelname"] + '_model_plot.png', show_shapes=True, show_layer_names=True)
    else:
        print("plotting model to file, not possible")
    return model

def get_ocSVM(config):
    oneclass=svm.OneClassSVM(kernel='linear', gamma=0.000001, nu=0.10)
    return oneclass

#Get the model
def getSAE_LSTM(config):
    #This is the size of our encoded representations
    encoding_dim1 = 60 
    encoding_dim2 = 35
    encoding_dim3 = 20
    
    # this is our input placeholder
    input = Input(shape=(config["nTimesteps"], config["nOperatingColumns"]))
    # "encoded" is the encoded representation of the input
    encoded = LSTM(encoding_dim1, return_sequences=True, dropout = 0.2)(input)
    
	#dropout will randomly make some cells void in generating the output. Makes the model better.
    encoded = LSTM(encoding_dim2, return_sequences=True, dropout = 0.2)(encoded)
    
	#return_sequences passes the sequences to the next layer. Since we have LSTM layers all the way, we need to pass the sequences to the next layers too. 
    encoded = LSTM(encoding_dim3, return_sequences=True, dropout = 0.2)(encoded)
    
    decoded = LSTM(encoding_dim2, return_sequences=True, dropout = 0.2)(encoded)
    
    decoded = LSTM(encoding_dim1, return_sequences=True, dropout = 0.2)(decoded)
    
    decoded = LSTM(config["nOperatingColumns"], return_sequences=True)(decoded)
    
    # this model maps an input to its reconstruction
    sae_lstm = Model(input, decoded)
    sae_lstm.compile(optimizer='adam', loss='mean_squared_error')
    
    return sae_lstm



def getSAE(config):
    encoding_dim1 = 60
    encoding_dim2 = 35
    encoding_dim3 = 20

    # this is our input placeholder.
    input = Input(shape=(config["nOperatingColumns"], ))
    # "encoded" is the encoded representation of the input
    encoded = Dense(encoding_dim1, activation = 'relu')(input)

    encoded = Dense(encoding_dim2, activation = 'relu')(encoded)

    encoded = Dense(encoding_dim3, activation = 'relu')(encoded)

    decoded = Dense(encoding_dim2, activation = 'relu')(encoded)

    decoded = Dense(encoding_dim1, activation = 'relu')(decoded)

    decoded = Dense(config["nOperatingColumns"], activation = 'sigmoid')(decoded)

    # this model maps an input to its reconstruction
    sequence_autoencoder = Model(input, decoded)

    # this model maps an input to its encoded representation
    encoder = Model(input,encoded)
    print("encoder summary:")
    encoder.summary()
    sequence_autoencoder.compile(optimizer='adam', loss='mean_squared_error')
    print("sequence_autoencoder summary:")
    sequence_autoencoder.summary()
    return sequence_autoencoder


def predict( model, config):
    prediction_result = []
    prediction_input = []
    rmse = None
    decisions = None
    if config["modelname"]=="ocSVM":
        prediction = model.decision_function(config["X_test"])
    elif config["modelname"]=="SAE":
        prediction = model.predict(config["X_test"])
    elif config["modelname"]=="SAE_LSTM":
        if config["nTimesteps"]==0:
            raise Exception("config[\"nTimesteps\"]==0")
        prediction = model.predict(config["X_test_sequence"] )
    else:
        raise Exception("Failed: get modelname " + config["modelName"] + " not existing")

    if config["modelname"]=="SAE_LSTM":
        #Removing timesteps in prediction result
        for i in range(len(prediction)):
            prediction_input.append(config["X_test_sequence"][i, 0, :])
            prediction_result.append(prediction[i, 0, :])
        prediction_input, prediction_result = np.array(prediction_input), np.array(prediction_result)
    elif config["modelname"]=="SAE":
        prediction_input=config["X_test"]
        prediction_result=prediction
    elif config["modelname"]=="ocSVM":
        prediction_input=config["y_test"]
        prediction_result=np.linalg.norm([prediction],axis=0)
    else:
        raise Exception("Failed: get modelname " + config["modelName"] + " not existing prediction step A")

    predictionsDir = config["resultDir"] + "predictions/"
    if not pathlib.Path(predictionsDir).exists():
        os.mkdir(predictionsDir)

    if (config["modelname"] == "SAE_LSTM") or (config["modelname"] == "SAE"):
        print("Calculating RMSE's...")
        mse = np.mean(np.power(prediction_input - prediction_result, 2), axis=1)
        print("sqrt RMSE's...")
        rmse = np.sqrt(mse)
        print("decide on rmse...")


        outputFileName = predictionsDir + "ReconstructionError_" + config["testname"] + ".csv"
        np.savetxt(outputFileName, rmse, delimiter=',', fmt="%s")
        fpr, tpr, thresholds_roc = roc_curve(config["y_test"], rmse)
        precision, recall, thresholds_pr = precision_recall_curve(config["y_test"], rmse)

        decisions = decide_batch(rmse)

    elif config["modelname"]=="ocSVM":
        outputFileName = predictionsDir + "predictions_" + config["testname"] + ".csv"
        np.savetxt(outputFileName, prediction_result, delimiter=',', fmt="%s")

        decisions = decide_batch(prediction_result)
        fpr, tpr, thresholds_roc = roc_curve(config["y_test"], prediction_result)
        precision, recall, thresholds_pr = precision_recall_curve(config["y_test"], prediction_result)
    else:
        raise Exception("Failed: get modelname " + config["modelName"] + " not existing prediction step B")

    fpr_tprDir = config["resultDir"] + "fpr_tpr/"
    if not pathlib.Path(fpr_tprDir).exists():
        os.mkdir(fpr_tprDir)

    np.savetxt(fpr_tprDir + config["testname"] + '-fpr.csv', fpr, delimiter="\n")
    np.savetxt(fpr_tprDir + config["testname"] + '-tpr.csv', tpr, delimiter="\n")

    precision_recallDir = config["resultDir"] + "precision_recall/"
    if not pathlib.Path(precision_recallDir).exists():
        os.mkdir(precision_recallDir)

    np.savetxt(precision_recallDir + config["testname"] + '-precision.csv', precision, delimiter="\n")
    np.savetxt(precision_recallDir + config["testname"] + '-recall.csv', recall, delimiter="\n")


    roc_auc = auc(fpr, tpr)
    pr_auc = auc(recall,precision)

    aucDir = config["resultDir"] + "auc_plots/"
    if not pathlib.Path(aucDir).exists():
        os.mkdir(aucDir)
    plt.figure()
    plt.plot(fpr, tpr, color='red', label='AUC = %0.3f)' % roc_auc)
    plt.xlim((0, 1))
    plt.ylim((0, 1))
    plt.plot([0, 1], [0, 1], color="navy", linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC ' + config["testname"])
    plt.legend(loc='lower right')
    plt.savefig(aucDir + "ROC-curve_" + "_" + config["testname"] + ".png")
    plt.show()

    plt.figure()
    plt.plot(recall,precision, color='red', label='AUC = %0.3f)' % pr_auc)
    plt.xlim((0, 1))
    plt.ylim((0, 1))
    plt.plot([0, 1], [0, 1], color="navy", linestyle='--')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('PR ' + config["testname"])
    plt.legend(loc='lower right')
    plt.savefig(aucDir + "PR-curve_" + "_" + config["testname"] + ".png")
    plt.show()

    return prediction_input,prediction_result, rmse, decisions,roc_auc,pr_auc


def get_mean_stdev(errors_list):
    mean = np.mean(errors_list)
    stdev = np.std(errors_list)
    return (mean, stdev)

def get_iqr(errors_list):
    qs = np.percentile(errors_list, [100, 75, 50, 25, 0])
    iqr = qs[1] - qs[3]
    MC = ((qs[0]-qs[2])-(qs[2]-qs[4]))/(qs[0]-qs[4])
    if MC >= 0:
        constant = 3
    else:
        constant = 4
    iqrplusMC = 1.5 * math.pow(math.e, constant * MC) * iqr
    return (qs[1], iqrplusMC)


def get_median_mad(errors_list):
    median = np.median(errors_list)
    mad = np.median([np.abs(error - median) for error in errors_list])
    return (median, mad)

def decide_batch(mse):
    decision = []
    t1,t2= get_mean_stdev(mse)
    results = np.greater(mse, (float(t1) + 2 * float(t2)))
    decision.append(results)

    t1, t2 = get_iqr(mse)
    results = np.greater(mse, (float(t1) + float(t2)))
    decision.append(results)

    t1, t2 = get_median_mad(mse)
    zscore = 0.6745 * (mse - float(t1)) / float(t2)
    resultsA = np.greater(zscore, 3.5)
    resultsB = np.less(zscore, -3.5)
    results = np.logical_or(resultsA, resultsB)
    decision.append(results)

    return decision

def getDecisionName(index):
    decisions = ["mean","iqr","zscore"]
    return decisions[index]
