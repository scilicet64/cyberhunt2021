from matplotlib import pyplot as plt
from matplotlib import style
import numpy as np
import pandas as pd
import pathlib
import os



orgtestfiles = ["custom_reconnaissance","custom_foothold","custom_lateralmovement","custom_dataexf","custom_sqli","custom_portscan","custom_xss","custom_bruteforce"]
overviewFile = "overview/overview_results.csv"
overview = pd.read_csv(overviewFile, header=0, encoding="ISO-8859-1")
overview = overview[overview["epochs"]==100]
overview = overview.round(3)
overview = overview.rename({"modelname":"Modelname"},axis="columns")
overview = overview.rename({"usePayload":"Payload"},axis="columns")
overview = overview.rename({"useFeatureScaling":"Scaling"},axis="columns")
overview = overview.rename({"roc_auc":"ROC_AUC"},axis="columns")
overview = overview.rename({"pr_auc":"PR_AUC"},axis="columns")
overview["Payload"] = overview["Payload"].astype(str)
overview["Scaling"] = overview["Scaling"].astype(str)

#,usePayload , useFeatureScaling
selection = {"custom_reconnaissance":[["ocSVM","False","False",0.899,0.681,"ocSCM no scaling"],
                                      ["ocSVM","False","True",0.816,0.550,"ocSCM with scaling"],
                                      ["SAE_LSTM","percentage","False",0.883,0.596,"SAE_LSTM with payload,no scaling"],
                                      ["SAE_LSTM","percentage","True",0.684,0.404,"SAE_LSTM with payload,with scaling"],
                                     # ["SAE","False","False",0.882,0.580,"SAE no payload,no scaling"],
                                      ["SAE","False","True",0.649,0.415,"SAE no payload, with scaling"]],
             "custom_foothold":[["ocSVM","False","False",0.944,0.781,"ocSCM no scaling"],
                                ["SAE_LSTM","percentage","False",0.918,0.617,"SAE_LSTM with payload,no scaling"],
                                ["ocSVM","percentage","True",0.901,0.722,"ocSCM with payload+scaling"],
                                ["SAE","absolute","True",0.828,0.633,"SAE with payload+scaling"],
                                ["SAE_LSTM","absolute","True",0.812,0.582,"SAE_LSTM with payload+scaling"]],
            "custom_lateralmovement":[["SAE","percentage","True",0.465,0.569,"SAE with payload+scaling"],
                                      ["SAE","percentage","False",0.348,0.373,"SAE with payload no scaling"],
                                      ["ocSVM","False","True",0.443,0.527,"ocSVM no payload with scaling"],
                                      ["ocSVM","percentage","True",0.378,0.501,"ocSVM with payload+scaling"],
                                      ["SAE","absolute","True",0.204,0.466,"SAE with payload+scaling"],
                                      ],
            "custom_dataexf":[["ocSVM","absolute","True",0.981,0.831,"ocSCM with payload+scaling"],
                                       ["SAE_LSTM","absolute","True",0.950,0.586,"SAE_LSTM with payload+scaling"],
                                       ["SAE","absolute","True",0.933,0.471,"SAE with payload+scaling"],
                                       #["ocSVM","absolute","False",0.828,0.234,"ocSCM with payload no scaling"],
                                       ["ocSVM","False","True",0.821,0.230,"ocSCM no payload with scaling"],
                                       #["SAE","False","True",0.346,0.078,"SAE no payload with scaling"],
                                       ["SAE_LSTM","False","True",0.246,0.069,"SAE_LSTM no payload with scaling"],


             ]
             }


colorCodes = ["r","b","g","m","y","k","c"]

for plottype in ["PR","ROC"]:
    style.use('ggplot')
    plt.rcParams.update({'font.size': 12})
    for key in selection.keys():
        colorCounter=0
        pltlabels=[]

        for experiment in selection[key]:
            modelname=experiment[0]
            payload = experiment[1]
            if payload=="absolute":
                payload="True"
            scaling = experiment[2]
            roc = experiment[3]
            pr = experiment[4]
            pltlabels = pltlabels + [experiment[5]]
            ix= overview[(overview["Modelname"]==modelname)&(overview["Payload"]==payload)&(overview["Scaling"]==scaling)&(overview["ROC_AUC"]==roc)&(overview["PR_AUC"]==pr)].index
            if len(ix)==1:
                id = overview.loc[ix, "id"].values[0]
                if plottype=="PR":
                    _resultsDir = "results/" + id + "/precision_recall/"
                    x = np.loadtxt(_resultsDir + key+ '-recall.csv', unpack=True)
                    y = np.loadtxt(_resultsDir + key+ '-precision.csv', unpack=True)
                else:
                    _resultsDir = "results/" + id + "/fpr_tpr/"
                    x = np.loadtxt(_resultsDir + key + '-fpr.csv', unpack=True)
                    y = np.loadtxt(_resultsDir + key + '-tpr.csv', unpack=True)
                plt.plot(x, y, colorCodes[colorCounter])
                colorCounter=colorCounter+1

            else:
                print("WARNING!!! not >1< model found")

        plt.legend(tuple(pltlabels),
                   prop={"size": 11}, loc='best')

        _figuresDir = "figures/"
        if not pathlib.Path(_figuresDir).exists():
            os.mkdir(_figuresDir)

        title = key.replace("custom_","").capitalize()
        title = title.replace("Lateralmovement","Lateral Movement")
        title = title.replace("Dataexf", "Data Exfiltration")
        title = title.replace("Foothold", "Establish Foothold")
        title = title + " Stage"

        filename = _figuresDir + plottype +  "_" + key.replace("custom_", "").capitalize() + ".pdf"
        plt.title(title)
        if plottype=="PR":
            plt.xlabel("Recall")
            plt.ylabel("Precision")
        else:
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
        ax = plt.gca()
        ax.set_facecolor('xkcd:white')
        ax.xaxis.label.set_color('black')
        ax.yaxis.label.set_color('black')
        ax.set_xticks(np.arange(0, 1, 0.1))
        ax.set_yticks(np.arange(0, 1., 0.1))
        ax.tick_params(axis='x', colors='black')
        ax.tick_params(axis='y', colors='black')
        plt.grid(color='black', linestyle='dashed')
        plt.savefig(filename,bbox_inches="tight")
        plt.show()

