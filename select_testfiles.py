import pandas as pd
import numpy as np
from os import listdir
from os.path import isfile, join

indir="data/freq_output/"
outdir="data/testfiles/"

def getfilename(selecttype,selectday,daylist):
    selecttype = selecttype.lower()
    selectday = selectday.lower()
    for day in daylist:
        if ((selecttype in day) and ((selectday in day) )):
            return day
    return None

csvfiles = [f for f in listdir(indir) if isfile(join(indir, f)) and filter(f)]
cyberhunttests = pd.read_csv(indir+"overview.csv",sep=",",header=0,decimal=".",index_col=False)
newoverview =[]
overvieworiginaltests = pd.read_csv(indir+"overview_apt2020tests.csv",sep=",",header=0,decimal=".",index_col=False)
filenames = overvieworiginaltests.groupby(["File"]).size().reset_index(name='counts')
for filename in filenames.values:
    ixfilename = filenames.columns.get_loc("File")
    currentfilename = filename[ixfilename]
    print(currentfilename)
    selection = overvieworiginaltests[overvieworiginaltests["File"]==currentfilename]
    ixnettype = selection.columns.get_loc("Nettype")
    ixday= selection.columns.get_loc("Day")
    ixactivity = selection.columns.get_loc("Activity")
    ixstage = selection.columns.get_loc("Stage")
    selectiondict = dict()
    for selectedtestfile in selection.values:
        nettype = selectedtestfile[ixnettype]
        day = selectedtestfile[ixday]
        activity = selectedtestfile[ixactivity]
        stage = selectedtestfile[ixstage]
        selectedfilename = getfilename(nettype,day,csvfiles)
        if selectedfilename!=None:
            if selectedfilename in selectiondict:
                 selectiondict[selectedfilename].append([activity,stage,nettype,day])
            else:
                selectiondict[selectedfilename]=[[activity, stage,nettype,day]]
        else:
            print("Warning could not select source file")
    testvalues=[]
    for inputfile in selectiondict.keys():
        selectedtestset = pd.read_csv(indir + inputfile, sep=",", header=0, decimal=".", index_col=False)
        indexes = []
        values = selectiondict[inputfile]
        for activity,stage,nettype,day in values:
            tempindexes =  selectedtestset[(selectedtestset["Activity"]==activity)&(selectedtestset["Stage"]==stage)].index.values.tolist()
            count = len(tempindexes)
            if count==0:
                print("Warning no selection for ", activity,stage, nettype,day, selectedfilename)
            indexes = indexes +tempindexes
            newoverview.append([currentfilename,nettype,day,activity,stage,count])
        indexes.sort()
        testvalues = testvalues + selectedtestset.iloc[indexes].values.tolist()
    if(len(testvalues)>0):
        newtestset = pd.DataFrame(testvalues,columns=selectedtestset.columns)
        newtestset["Timestamp"] = pd.to_datetime(newtestset["Timestamp"])
        newtestset = newtestset.sort_values(by="Timestamp")
        newtestset.to_csv(outdir+currentfilename, sep=",", decimal=".", index=False)


overviewfile = outdir+"overview_cyberhunttests.csv"
overview = pd.DataFrame(newoverview,columns=["File","Nettype","Day","Activity","Stage","Counts"])
print("Writing overview file",overviewfile)
overview.to_csv(overviewfile,sep=",",decimal=".",index=False)

