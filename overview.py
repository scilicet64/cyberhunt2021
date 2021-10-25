import pandas as pd
import numpy as np
import sys

#lateralmovement = pd.read_csv("data/testfiles/custom_lateralmovement.csv", header=0, encoding="ISO-8859-1")
#lateralmovement["Timestamp"] = pd.to_datetime(lateralmovement["Timestamp"])
#lmgroup = lateralmovement.groupby(["Activity","Stage",lateralmovement["Timestamp"].dt.day_name()]).size()
renamedict ={"dataexf":"Data Exfiltration","lateralmovement":"Lateral Movement"}
orgtestfiles = ["custom_reconnaissance","custom_foothold","custom_lateralmovement","custom_dataexf","custom_sqli","custom_portscan","custom_xss","custom_bruteforce"]

testoverviewFile = "data/testfiles/overview_cyberhunttests.csv"
testfilesoverview = pd.read_csv(testoverviewFile, header=0, encoding="ISO-8859-1")
df = testfilesoverview.groupby(["File","Activity"], as_index=False).sum()
df["showorder"]=-1
for index,test in enumerate(orgtestfiles):
    ix = df[df["File"]==test + ".csv"].index
    newtest = test.replace("custom_","")
    if newtest in renamedict:
        newtest = renamedict[newtest]
    df.loc[ix,"File"]=newtest
    df.loc[ix, "showorder"]=index
df=df[df["showorder"]!=-1]
df= df.sort_values("showorder").drop("showorder",1)
df["File"] = df["File"].str.capitalize()
df = df.rename({"File":"APT Stage"},axis="columns")
print(df)
with open("overview/overview_tests.tex", "w") as TEXfile:
    tex = df.to_latex(index=False,caption="Dataset Distribution",label="Hunt2021Distribution")
    TEXfile.write(tex)
    TEXfile.write("\n")

pcapnormalpackets = 670037 #monday public
print(testfilesoverview)



overviewFile = "overview/overview_results.csv"
overview = pd.read_csv(overviewFile, header=0, encoding="ISO-8859-1")
overview = overview[overview["epochs"]==100]
overview = overview.sort_values("pr_auc",ascending=False)
ixid = overview.columns.get_loc("id")
ixtestname = overview.columns.get_loc("testname")
ixmodelname = overview.columns.get_loc("modelname")
ixusepayload = overview.columns.get_loc("usePayload")
ixuseFeatureScaling = overview.columns.get_loc("useFeatureScaling")

ixroc_auc = overview.columns.get_loc("roc_auc")
tests = overview.groupby(["testname"]).size().index.values.tolist()
if len(set(tests).difference(set(orgtestfiles)))>0:
    print("WARNING", tests,"not same as orgtestfiles ", orgtestfiles)
    sys.exit(-1)
modelnames = overview.groupby(["modelname"]).size().index.values.tolist()

overview = overview.rename({"modelname":"Modelname"},axis="columns")
overview = overview.rename({"usePayload":"Payload"},axis="columns")
overview = overview.rename({"useFeatureScaling":"Scaling"},axis="columns")
overview = overview.rename({"roc_auc":"ROC_AUC"},axis="columns")
overview = overview.rename({"pr_auc":"PR_AUC"},axis="columns")

show_columns= ["Modelname","Payload","Scaling","ROC_AUC","PR_AUC"]

latex_columns=[]
latex_header = ""
for index,column in enumerate(show_columns):
    latex_columns.append("\\textbf{" + column + "}")
    latex_header = latex_header + "\\textbf{" + column.replace("_","\\_") + "}"
    if index<len(show_columns)-1:
        latex_header = latex_header + " & "
    else:
        latex_header = latex_header + " \\\\"
print(latex_columns)
print(latex_header)

ix = overview[(overview["Modelname"]=="SAE_LSTM")&(overview["sorted"]=="sortedDstPort")].index
overview = overview.drop(index=ix) # REMOVED SAE_LSTM_SORTED no improvement

ix = overview[(overview["Scaling"]==False)].index
overview.loc[ix,"Scaling"]=""

ix = overview[(overview["Scaling"]==True)].index
overview.loc[ix,"Scaling"]="checkmark"

ix = overview[(overview["Payload"]=="False")].index
overview.loc[ix,"Payload"]=""

ix = overview[(overview["Payload"]=="True")].index
overview.loc[ix,"Payload"]="absolute"

overview = overview.round(3)


#overview = overview.drop("sorted",axis=1)

with open("overview/overview_results.txt","w") as textfile:
    with open("overview/overview_results.tex", "w") as TEXfile:
        for test in orgtestfiles:
            print("testname: ",test)
            textfile.write("\ntestname: " + test + "\n")

            df_best_test = overview[(overview["testname"]==test)].sort_values(["ROC_AUC","PR_AUC"],ascending=False)[show_columns]
            group = df_best_test.groupby(["Modelname","Scaling","ROC_AUC","PR_AUC"]).size()
            group_result = (group > 1).values
            for index,mergeable in enumerate(group_result):
                if mergeable:
                    modelname = group.index[index][0]
                    scaling = group.index[index][1]
                    rocauc = group.index[index][2]
                    prauc = group.index[index][3]
                    ix= df_best_test[(df_best_test["Modelname"]==modelname)&(df_best_test["Scaling"]==scaling)&(df_best_test["ROC_AUC"]==rocauc)&(df_best_test["PR_AUC"]==prauc)].index
                    if len(ix)==group.values[index]==3:
                        df_best_test.loc[ix[0],"Payload"] = "*"
                        df_best_test = df_best_test.drop(index=ix[1:3])
                    elif len(ix) == group.values[index] ==2:
                        df_best_test.loc[ix[0], "Payload"] = "+"
                        df_best_test = df_best_test.drop(index=ix[1])
                    else:
                        print("WARNING ERROR!!!!")

            group = df_best_test.groupby(["Modelname","Payload","ROC_AUC","PR_AUC"]).size()
            group_result = (group > 1).values
            for index,mergeable in enumerate(group_result):
                if mergeable:
                    modelname = group.index[index][0]
                    payload = group.index[index][1]
                    rocauc = group.index[index][2]
                    prauc = group.index[index][3]
                    ix= df_best_test[(df_best_test["Modelname"]==modelname)&(df_best_test["Payload"]==payload)&(df_best_test["ROC_AUC"]==rocauc)&(df_best_test["PR_AUC"]==prauc)].index
                    if len(ix)==group.values[index]==2:
                        df_best_test.loc[ix[0],"Scaling"] = "*"
                        df_best_test = df_best_test.drop(index=ix[1:3])
                    else:
                        print("WARNING ERROR!!!!")



            print(df_best_test)
            textfile.write(str(df_best_test))
            textfile.write("\n\n\n\n")
            test= test.replace("custom_","")
            caption = test.replace("_","\\_")
            caption = caption.replace("dataexf", "Data Exfiltration")
            caption = caption.replace("lateralmovement", "Lateral Movement")
            caption = caption.replace("foothold", "Establish Foothold")
            label = "tab_" + test
            tex = df_best_test.to_latex(index=False,caption=caption,label=label)
            toprule = tex.find("\\toprule")
            midrule = tex.find("\\midrule")
            header = tex[toprule:midrule]
            tex = tex.replace(header,"\\toprule\n"+latex_header+"\n")

            tex = tex.replace("{tabular}{lllrr}","{tabular}{|l|l|c|c|c|}")
            tex = tex.replace("checkmark","\\checkmark")
            tex = tex.replace("\\centering", "\\begin{center}")
            tex = tex.replace("\\bottomrule", "\\hline")
            tex = tex.replace("\\midrule", "\\hline")
            tex = tex.replace("\\toprule", "\\hline")
            tex = tex.replace("\\end{table}", "\\end{center}\n\\end{table}")
            tex = tex.replace("\\begin{table}", "\\begin{table}[htbp]")

            TEXfile.write(tex)
            TEXfile.write("\n")