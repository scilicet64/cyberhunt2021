# -*- coding: utf-8 -*-
"""
Created on Mon Jul 29 22:09:09 2019

@author: Sowmya
"""
#This python program is used for labeling network flow logs based on the ip address and the timestamp of the activity
#Example Run: labeler.py [filePath] [fileName_without_extension] [ipAddress] [startTime-DD/MM/YYYY HH:MM:SS AM] [endTime-DD/MM/YYYY HH:MM:SS AM]
##Example Run: labeler.py "C:\Users\APT\Documents\Scanner" "day-2-flow-logs" "123.23.21.12" "15/07/2019 01:45:37 PM" "15/07/2019 01:45:37 PM"

import sys
import pandas as pd
import numpy as np

from dateutil import parser

fileName = sys.argv[1]
ipAddress = sys.argv[2]
startTime = parser.parse(sys.argv[3])
endTime = parser.parse(sys.argv[4])
activity = ["Web Vulnerability Scan", "Network Scan", "Account Discovery", "Directory Bruteforce", "Account Bruteforce", "SQL Injection", "Privilege Escalation", "Password Dump", "Data Exfiltration"]
stage = ["Reconnaissance", "Establish Foothold", "Lateral Movement", "Data Exfiltration"]

print("Please make a copy of the original file to read")

for i in range(len(activity)):
    print(str(i) + " - " + activity[i])
activityIndex = int(input("Please enter the index of the activity from above that you want to label the records with\n"))

for i in range(len(stage)):
    print(str(i) + " - " + stage[i])
stageIndex = int(input("Please enter the index of the stage from above that you want to label the records with\n"))

#activityIndex = 1
#stageIndex = 0

fileToRead = fileName + ".csv"

print("file to read is : " + str(fileToRead))
input_file = pd.read_csv(fileToRead, header=0, encoding="ISO-8859-1")

records = np.array(input_file)
stageColumn = []

if records.shape[1] < 85:
    for i in range(records.shape[0]):  
        if i == 0:
            records[i,-1] = "Activity"
            stageColumn.append("Stage")
        else:
            records[i,-1] = "Normal"
            stageColumn.append("Benign")
    stageColumn = np.reshape(stageColumn, (records.shape[0], 1))
    records = np.append(records, stageColumn, axis=1)

nCount = 0
for i in range(records.shape[0]):  
    #if records[i, 1] == ipAddress:
    #    print(records[i, 1] + ", " + str(i))
    if records[i, 1] == ipAddress and parser.parse(records[i, 6]) >= startTime and parser.parse(records[i, 6]) <= endTime:
        nCount = nCount + 1
        records[i,-2] = activity[activityIndex]
        records[i, -1] = stage[stageIndex]
        
np.savetxt(fileToRead, np.array(records[:, :]), delimiter=',', fmt="%s")
print("\n" + str(nCount) + " Records have been udpated in the file\n")        
