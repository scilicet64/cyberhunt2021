import pandas as pd
import numpy as np
from os import listdir
from os.path import isfile, join


testdir="apt-2020-code/data/"#https://gitlab.thothlab.org/Advanced-Persistent-Threat/apt-2020.git
csvdir="apt-2020-raw/csv/" #https://gitlab.thothlab.org/achaud16/apt.git
outdir="data/freq_output/"


days = ["monday","tuesday","wednesday","thursday","friday"]
types = ["pvt","public"]

iplist=[]
csvfiles = [f for f in listdir(csvdir) if isfile(join(csvdir, f)) and f.endswith("_Flow.csv")]
for csvfile in csvfiles:
    currentday=""
    currenttype=""
    for day in days:
        if day in csvfile:
            currentday=day
    for nettype in types:
        if nettype in csvfile:
            currenttype=nettype
    if currenttype=="":
        currenttype="public"
        print("warning: ", currentday, "set to default type")
    print("day", currentday, "nettype", currenttype)
    dataset = pd.read_csv(csvdir+csvfile,sep=",",header=0,decimal=".",index_col=False)
    x = dataset.groupby(["Src IP","Dst IP"]).size().reset_index(name='counts')
    for stats in x.values:
        line = [csvfile,currentday,currenttype] + stats.tolist()
        iplist.append(line)
_iplist = pd.DataFrame(iplist,columns=["File","Day","Nettype","Src IP","Dst IP","Counts"])
iplistfile=csvdir + "iplist.csv"
_iplist.to_csv(iplistfile,sep=",",decimal=".",index=False)


def testfilter(filename):
    if filename.startswith("custom_") and filename.endswith(".csv"):
        print(filename)
        return True
    else:
        return False

testfiles = [f for f in listdir(testdir) if isfile(join(testdir, f)) and testfilter(f)]
overview = []
columns = "Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Total Fwd Packet,Total Bwd packets,Total Length of Fwd Packet,Total Length of Bwd Packet,Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,Bwd Packet Length Max,Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd Header Length,Bwd Header Length,Fwd Packets/s,Bwd Packets/s,Packet Length Min,Packet Length Max,Packet Length Mean,Packet Length Std,Packet Length Variance,FIN Flag Count,SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,CWR Flag Count,ECE Flag Count,Down/Up Ratio,Average Packet Size,Fwd Segment Size Avg,Bwd Segment Size Avg,Fwd Bytes/Bulk Avg,Fwd Packet/Bulk Avg,Fwd Bulk Rate Avg,Bwd Bytes/Bulk Avg,Bwd Packet/Bulk Avg,Bwd Bulk Rate Avg,Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes,FWD Init Win Bytes,Bwd Init Win Bytes,Fwd Act Data Pkts,Fwd Seg Size Min,Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,Activity,Stage"
columns = columns.split(",")
print("using nr of columns:" , len(columns))
for testfile in testfiles:
    print("reading ", testfile)
    file1 = open(testdir+testfile, 'r')
    line = file1.readline()
    file1.close()
    if "IP" in line:
        dataset = pd.read_csv(testdir+testfile,sep=",",header=0,decimal=".",index_col=False)
    else:
        dataset = pd.read_csv(testdir+testfile,sep=",",decimal=".",index_col=False)
        if len(dataset.columns)!=len(columns):
            print("skipping file:", testfile, " not same columns", str(len(dataset.columns)))
            continue
        dataset.columns = columns

    dataset["Timestamp"] = pd.to_datetime(dataset["Timestamp"])
    dataset["Activity"] = dataset["Activity"].str.strip()
    dataset["Stage"] = dataset["Stage"].str.strip() ##remove whitespaces in some files
    dataset["Activity"][dataset["Activity"]=="BENIGN"] = "Normal"
    dataset["Stage"][dataset["Stage"]=="BENIGN"]="Benign"
    groupediplist = dataset.groupby(["Activity","Stage",dataset["Timestamp"].dt.day_name(),"Src IP","Dst IP"]).size().reset_index(name='counts').values
    foundnettype = ""
    for ipline in groupediplist:
        act,stg,day,srcip,dstip,count = ipline
        day = day.lower()
        foundip = _iplist[(_iplist["Src IP"]==srcip)&(_iplist["Dst IP"]==dstip)&(_iplist["Day"]==day)]
        if len(foundip)==1:
            nettype = foundip["Nettype"].values[0]
            if nettype!= foundnettype:
                if foundnettype!="":
                    print("warning: nettype switched back")
                foundnettype=nettype
                print("found nettype:", nettype)

    x = dataset.groupby(["Activity","Stage",dataset["Timestamp"].dt.day_name()]).size().reset_index(name='counts')
    print(x.values)
    for stats in x.values:
        line = [testfile,foundnettype] + stats.tolist()
        overview.append(line)

overviewfile = outdir+"overview_apt2020tests.csv"
overview = pd.DataFrame(overview,columns=["File","Nettype","Activity","Stage","Day","Counts"])
print("Writing overview file",overviewfile)
overview.to_csv(overviewfile,sep=",",decimal=".",index=False)