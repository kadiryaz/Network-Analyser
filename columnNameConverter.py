import pandas as pd

csvFileName = "CIC-ToN-IoT"
dataset = pd.DataFrame()
print("Dataset is being read")
foo = pd.read_csv(csvFileName+".csv",iterator=True,chunksize=50000)
for chunk in foo:
 dataset= pd.concat([dataset,chunk])

dataset.columns = dataset.columns.str.lower() 
dataset.columns = dataset.columns.str.replace(' ','_') 
print("Columns has been changed. New CSV file will be saved")

dataset.to_csv(csvFileName + "_fixed.csv")
print(csvFileName+"_fixed.csv has been saved")