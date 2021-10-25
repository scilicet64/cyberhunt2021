import pandas as pd
import numpy as np
from os import listdir
from os.path import isfile, join
overview = []
labels = [
    ["enp0s3-public-tuesday.pcap_Flow.csv","184.98.36.245","16/07/2019 07:00:00 PM","16/07/2019 07:20:00 PM","*","Network Scan,Reconnaissance",362],
    ["enp0s3-public-tuesday.pcap_Flow.csv","184.98.36.245","16/07/2019 07:28:00 PM","16/07/2019 07:34:00 PM","9000","Web Vulnerability Scan,Reconnaissance",2411],
    ["enp0s3-public-tuesday.pcap_Flow.csv","184.98.36.245","16/07/2019 07:35:00 PM","16/07/2019 07:41:00 PM","9002","Web Vulnerability Scan,Reconnaissance",163],
   # ["enp0s3-public-tuesday.pcap_Flow.csv","184.98.36.245","16/07/2019 07:42:00 PM","16/07/2019 07:50:00 PM","9003","Web Vulnerability Scan,Reconnaissance",0],#not in set (also: 0)
    ["enp0s3-public-tuesday.pcap_Flow.csv","184.98.36.245","16/07/2019 08:00:00 PM","16/07/2019 08:20:00 PM","9002","Account BruteForce,Reconnaissance",50],
    ["enp0s3-public-tuesday.pcap_Flow.csv","184.98.36.245","16/07/2019 08:30:00 PM","16/07/2019 08:50:00 PM","*","Network Scan,Reconnaissance",488],
    ["enp0s3-public-wednesday.pcap_Flow.csv","184.98.36.245","17/07/2019 07:20:00 PM","17/07/2019 07:25:00 PM","9002","Account Bruteforce,Reconnaissance",44],
    ["enp0s3-public-wednesday.pcap_Flow.csv","184.98.36.245","17/07/2019 07:25:01 PM","17/07/2019 07:28:00 PM","9002","CSRF,Establish Foothold",7],
    ["enp0s3-public-wednesday.pcap_Flow.csv","184.98.36.245","17/07/2019 07:33:00 PM","17/07/2019 07:39:00 PM","9002","SQL Injection,Establish Foothold",30],
    ["enp0s3-public-wednesday.pcap_Flow.csv","192.168.3.29-206.207.50.50", "17/07/2019 10:03:00 PM","17/07/2019 10:06:00 PM","*","Malware Download,Establish Foothold",2],
    ["enp0s3-public-thursday.pcap_Flow.csv","192.168.3.29", "18/07/2019 08:05:00 PM","18/07/2019 09:01:00 PM","4444","Backdoor,Lateral Movement",20],
    ["enp0s3-pvt-friday.pcap_Flow.csv","192.168.3.30-206.207.50.50","19/07/2019 10:21:00 PM","19/07/2019 10:22:00 PM","*","Data Exfiltration,Data Exfiltration",0],
    ["enp0s3-public-friday.pcap_Flow.csv","184.98.36.245","19/07/2019 06:44:00 PM","19/07/2019 06:44:59 PM","9002","Command Injection,Establish Foothold",12]
]
days = ["monday","tuesday","wednesday","thursday","friday"]
types = ["pvt","public"]

indir="data/flow_gen/"
outdir="data/freq_output/"


csvfiles = [f for f in listdir(indir) if isfile(join(indir, f))]
for label in labels:
    infile, srcip, starttime, endtime, dstport, activities, nrresults = label
    if infile not in csvfiles:
       print("got labels for ", infile, ", but not found in ", outdir)


#csvfiles= ["enp0s3-monday.pcap_Flow.csv"]
for csvfile in csvfiles:
    if ".csv" not in csvfile:
        continue

    print("reading", csvfile)
    dataset = pd.read_csv(indir+csvfile,sep=",",header=0,decimal=".",index_col=False)

    dataset["Timestamp"] = pd.to_datetime(dataset["Timestamp"])
    ixpayload =dataset.columns.get_loc("Payload0")
    print("processing payload percentages", csvfile)
    for x in range(0,256):
        word = "PayloadPerc" + str(x)
        dataset[word]=0.0
    dataset["PayloadCounter"] = dataset.iloc[:,ixpayload:ixpayload+255].sum(axis=1)
    payloadcounter = dataset["PayloadCounter"][dataset["PayloadCounter"]>0]

    ixpayloadPerc0 =dataset.columns.get_loc("PayloadPerc0")
    ixpayload0 =dataset.columns.get_loc("Payload0")
    ixpayloadcounter =dataset.columns.get_loc("PayloadCounter")
    #result dataset.iloc[payloadcounter.index,ixpayload]
    #abspayload dataset.iloc[payloadcounter.index,ixpayload0]
    #counter dataset.iloc[payloadcounter.index,ixpayloadcounter]
    for x in range(0,256):
        dataset.iloc[payloadcounter.index,ixpayloadPerc0+x] = dataset.iloc[payloadcounter.index,ixpayload0+x] / dataset.iloc[payloadcounter.index,ixpayloadcounter]
    cols = dataset.columns.tolist()
    for column in ["Labels","Activity","Stage"]:
        if column in dataset.columns:
            cols.remove(column)
            cols.append(column)
            q=len(dataset[dataset[column]=="NeedManualLabel"])
            ix=[]
            if q>0:
                print(str(q) + "x NeedManualLabel found in " + column)
                ix = dataset[dataset[column]=="NeedManualLabel"].index
            elif dataset[column].isnull().values.any():
                print("nan found in " + column)
                ix = dataset[dataset[column].isnull()==True].index
            if len(ix)>0:
                ixlabel =dataset.columns.get_loc(column)
                dataset.iloc[ix,ixlabel]="BENIGN"
    dataset = dataset[cols] #reordered with found labels
    dataset["Activity"] = dataset["Activity"].str.strip()
    dataset["Stage"] = dataset["Stage"].str.strip() ##remove whitespaces in some files
    dataset["Activity"][dataset["Activity"]=="BENIGN"]="Normal"
    dataset["Stage"][dataset["Stage"]=="BENIGN"]="Benign"
    foundlabels=False
    for label in labels:
        infile,srcip,starttime,endtime,dstport,activities,nrresults =label
        if infile==csvfile:
            nrresults=int(nrresults)
            foundlabels=True
            dstip=None
            if "-" in srcip:
                srcip,dstip = srcip.split("-")
            selection = dataset[((dataset["Src IP"]==srcip)|(dataset["Dst IP"]==srcip))& (dataset["Timestamp"]>=starttime)& (dataset["Timestamp"]<=endtime) ].index
            if dstport!="*":
                dstport=int(dstport)
                selection = dataset.iloc[selection][(dataset.iloc[selection]["Src Port"]==dstport)|(dataset.iloc[selection]["Dst Port"]==dstport)].index
                #& ((dataset["Src Port"]==int(dstport))|(dataset["Dst Port"]==int(dstport)) )
            if dstip!=None:
                selection = dataset.iloc[selection][((dataset.iloc[selection]["Src IP"]==srcip)&(dataset.iloc[selection]["Dst IP"]==dstip))|((dataset.iloc[selection]["Src IP"]==dstip )&(dataset.iloc[selection]["Dst IP"]==srcip)) ].index


            allcount,normalcount = len(selection),len(dataset.iloc[selection][dataset.iloc[selection]["Activity"]=="Normal"])
            activity,stage = activities.split(",")
            activity=activity.strip()
            stage=stage.strip()
            dataset.iloc[selection,dataset.columns.get_loc("Activity")]=activity
            dataset.iloc[selection,dataset.columns.get_loc("Stage")]=stage
            print("all: %d normal: %d malicious: %d original %d"%(allcount,normalcount,(allcount-normalcount),nrresults))
            print(infile,srcip,starttime,endtime,dstport,activities,nrresults)
    if not foundlabels:
        print("no labels for ",csvfile)
    x = dataset.groupby(["Activity","Stage"]).size().reset_index(name='counts')
    print(x.values)
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
    for stats in x.values:
        line = [csvfile,currenttype,currentday] + stats.tolist()
        overview.append(line)
    outfile = outdir + csvfile
    print("Writing file",outfile)
    dataset.to_csv(outfile,sep=",",decimal=".",index=False)
overviewfile = outdir+"overview.csv"
overview = pd.DataFrame(overview,columns=["File","Nettype","Day","Activity","Stage","Counts"])
print("Writing overview file",overviewfile)
overview.to_csv(overviewfile,sep=",",decimal=".",index=False)
