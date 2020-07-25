# coding=utf-8
import csv
import shutil
import pandas as pd
# df1 = pd.read_csv("afl_result/verify_result.csv",low_memory=False)
# df2 = pd.read_csv("afl_result/libressl_result.csv")
# # df1.merge(df2,on='file_name',how='left')
# df3 = pd.merge(df1,df2,how='left',on='file_name')
# df3.to_csv("afl_result/result2.csv",index=False)
diffFile = open("afl_result/unique_diff.csv", "w")
diffFile2 = open("afl_result/diff.csv", "w")
fileheader = ["file_name","open_state", "gnu_state","mbed_state","nss_state","wolf_state","libressl_state"]
fileheader2 = ["file_name","open_state", "gnu_state","mbed_state","nss_state","wolf_state","libressl_state"]
dict_writer = csv.DictWriter(diffFile, fileheader)
dict_writer.writeheader()
# fileheader2 = ["file_name"]
dict_writer2 = csv.DictWriter(diffFile2, fileheader2)
dict_writer2.writeheader()
csvFile=open("afl_result/verify_result.csv", "r")
dict_reader = csv.DictReader(csvFile)
diff_num=0
diff=[]
unique_diff=[]
unique_state=[]#触发diff的验证返回值
cert_num =0
for row in dict_reader:
    cert_num=cert_num+1
    if not((row["open_state"]=='0'and row["gnu_state"]=='0'and row["mbed_state"]=='0'and row["nss_state"]=='0'and
             row["wolf_state"]=='0'and row["libressl_state"]=='0') or (row["open_state"]!='0'and row["gnu_state"]!='0'and row["mbed_state"]!='0'and row["nss_state"]!='0'and
             row["wolf_state"]!='0'and row["libressl_state"]!='0')):
        diff_num=diff_num+1
        diff.append(row)
        state=[]
        state.append(row["open_state"])
        state.append(row["gnu_state"])
        state.append(row["mbed_state"])
        state.append(row["nss_state"])
        state.append(row["wolf_state"])
        state.append(row["libressl_state"])
        if state not in unique_state:
            unique_state.append(state)
            unique_diff.append(row)
print ("cert num is "+str(cert_num))
print ("diff num is "+str(diff_num))
print ("unique diff num is "+str(len(unique_diff)))
for item in unique_diff:
    # print (item)
    dict_writer.writerow(item)
for item in diff:
    dict_writer2.writerow(item)
diffFile.close()

