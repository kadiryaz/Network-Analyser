import pandas as pd
import numpy as np
import csv
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score,classification_report
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import pickle

csvFileName = "fixedDataset1.csv"
modelName = "myRandomForestModel.pkl"

def removeUselessColumns(df):
    droppable = ['Unnamed: 0','idle_mean', 'idle_std', 
                 'idle_max', 'idle_min','bwd_psh_flags',
                   'fwd_urg_flags', 'bwd_urg_flags', 'urg_flag_cnt',
                     'fwd_byts/b_avg', 'fwd_pkts/b_avg',
                       'fwd_blk_rate_avg', 'subflow_bwd_pkts'] #default column Unnamed: 0   
    df.drop(columns=droppable,axis=1,inplace=True,errors='ignore')

def fixIPAdresses(df):
    myReplacerLambda = lambda x: int(x.replace('.', ''))
    df['src_ip'] = df['src_ip'].apply(myReplacerLambda) 
    df['dst_ip'] = df['dst_ip'].apply(myReplacerLambda) 
    df=df.astype({"src_ip":float})
    df=df.astype({"dst_ip":float})

def dropIPColumns(df):
    df.drop(columns=["src_ip"],axis=1,inplace=True)
    df.drop(columns=["dst_ip"],axis=1,inplace=True)

#def dropIdleColumns(df):
    #df.drop(columns=['idle_mean', 'idle_std', 'idle_max', 'idle_min'],axis=1,inplace=True)

#we don't interested in timestamp for now
def dropTimeStamp(df):
    df.drop(columns=["timestamp"],axis=1,inplace=True)

def trainModel(data,model,le):
    try:
        print("Data is being trained")
        removeUselessColumns(data)
        dropIPColumns(data)
        dropTimeStamp(data)
        #print(data)
        
    
        #turn labels to numeric value
        data["attack"] = le.fit_transform(data["attack"])
        le_name_mapping = dict(zip(le.classes_,le.transform(le.classes_)))
        print(le_name_mapping)
        data=data.astype({"attack":int})
        #x = data withot label values
        X = data.drop(columns=["label","attack"],axis=1)
        X= X.replace([np.inf, -np.inf], np.nan)
        X.fillna(999,inplace=True)
        #y= labels
        Y = data["attack"]
        #model.fit(X,Y)
        #split data for creating trained data and test data
        X_train,X_test,Y_train,Y_test = train_test_split(X,Y,stratify=Y,random_state=42,test_size=0.2)
        model.fit(X_train, Y_train)
        Y_pred = model.predict(X_test)
        print("Model has been trained. Accuracy is;")
        print(accuracy_score(Y_pred, Y_test))
    except Exception as err:
        print(err)
        print("An error occured. Skipping to other chunk")
        
def saveModel(model):
    global modelName
    pickle.dump(model,open(modelName,'wb'))
    print("Model has been saved as:" + modelName)


def testTrainedModel(data):
    print("Model is being tested")
    global model
    droppable = ['Unnamed: 0','idle_mean', 'idle_std', 
                 'idle_max', 'idle_min','bwd_psh_flags',
                   'fwd_urg_flags', 'bwd_urg_flags', 'urg_flag_cnt',
                     'fwd_byts/b_avg', 'fwd_pkts/b_avg',
                       'fwd_blk_rate_avg', 'subflow_bwd_pkts'] #default column Unnamed: 0   
    data.drop(columns=droppable,axis=1,inplace=True,errors='ignore')
    data.drop(columns=["timestamp"],axis=1,inplace=True,errors='ignore')
    data.drop(columns=["src_ip"],axis=1,inplace=True,errors='ignore')
    data.drop(columns=["dst_ip"],axis=1,inplace=True,errors='ignore')
    data = data.drop(columns=["label","attack"],axis=1,errors='ignore')
    data= data.replace([np.inf, -np.inf], np.nan)
    data.fillna(999,inplace=True)
    predictedValues = model.predict(data)
    print(predictedValues) 



le = LabelEncoder()
#createModel
model = RandomForestClassifier(n_estimators=10)
myLongDataset = pd.DataFrame()
myShortDataset = pd.DataFrame()
foo = pd.read_csv(csvFileName,iterator=True,chunksize=50000)
print("Dataset is reading")
#firstFrameCollected = False
testModeActive= True
i =0
for chunk in foo:
    if i >= 30:
        break;#enough for our system
    print("50k rows being read")
    myLongDataset= pd.concat([myLongDataset,chunk])
    myShortDataset = chunk #hold the last chunk
    i=i+1

del foo
trainModel(myLongDataset,model,le)

#test your model before saving it
testTrainedModel(myShortDataset)
saveModel(model)

