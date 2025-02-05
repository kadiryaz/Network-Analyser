import pandas as pd
import numpy as np
import pickle
from sklearn.metrics import accuracy_score,classification_report
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

####initial values
le_name_mapping = {0:'Benign', 1: 'backdoor', 2: 'ddos', 
                   3: 'dos', 4: 'injection', 5: 'mitm',
                   6: 'password', 7: 'ransomware', 
                   8: 'scanning', 9: 'xss'}



fixedColumns = ['src_port', 'dst_port', 'protocol',
       'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts',
       'totlen_fwd_pkts', 'totlen_bwd_pkts', 'fwd_pkt_len_max',
       'fwd_pkt_len_min', 'fwd_pkt_len_mean', 'fwd_pkt_len_std',
       'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean',
       'bwd_pkt_len_std', 'flow_byts/s', 'flow_pkts/s', 'flow_iat_mean',
       'flow_iat_std', 'flow_iat_max', 'flow_iat_min', 'fwd_iat_tot',
       'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
       'bwd_iat_tot', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max',
       'bwd_iat_min', 'fwd_psh_flags',
        'fwd_header_len', 'bwd_header_len', 'fwd_pkts/s',
       'bwd_pkts/s', 'pkt_len_min', 'pkt_len_max', 'pkt_len_mean',
       'pkt_len_std', 'pkt_len_var', 'fin_flag_cnt', 'syn_flag_cnt',
       'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt',
       'cwe_flag_count', 'ece_flag_cnt', 'down/up_ratio', 'pkt_size_avg',
       'fwd_seg_size_avg', 'bwd_seg_size_avg', 
         'bwd_byts/b_avg',
       'bwd_pkts/b_avg', 'bwd_blk_rate_avg', 'subflow_fwd_pkts',
       'subflow_fwd_byts', 'subflow_bwd_byts',
       'init_fwd_win_byts', 'init_bwd_win_byts', 'fwd_act_data_pkts',
       'fwd_seg_size_min', 'active_mean', 'active_std', 'active_max',
       'active_min']

modelFileName = "myRandomForestModel.pkl"
#testDataFileName = "CIC-ToN-IoT_fixed"
#testDataFileName = "testDataWithAttacks_fixed"
testDataFileName = ""
####

####functions
def prepareTestData(testData):
    global fixedColumns
    #drop other columns
    testData = testData[testData.columns.intersection(fixedColumns)]
    #sort the columns as same with trained data
    testData = testData[fixedColumns]
    droppable = ['Unnamed: 0','bwd_psh_flags',
                'bwd_urg_flags','fwd_blk_rate_avg',
                'fwd_byts/b_avg','fwd_pkts/b_avg',
                'fwd_urg_flags','idle_max',
                'idle_mean','idle_min','idle_std',
                'label','subflow_bwd_pkts',
                'timestamp','urg_flag_cnt','attack','dst_ip'
                ,'src_ip','flow_id']
    testData.drop(columns=droppable,inplace=True,errors='ignore')
    testData= testData.replace([np.inf, -np.inf], np.nan)
    testData.fillna(999,inplace=True)
    print("Data has been prepared")
    return testData




def predictTheCollectedData(testData,model):
    try:
        #testData = pd.read_csv(testDataFileName+".csv")
        testData = prepareTestData(testData)
        print(testData)
        predictedLabels = model.predict(testData)
        print("Test data has been predicted")
        return predictedLabels
    except:
        print("An error occured. Skipping this chunk")
        predictedLabels = [0] * len(testData.index)
        return predictedLabels
####   




####Main

def main():
    model = pickle.load(open(modelFileName,'rb'))


    resultData = pd.DataFrame()
    resultLabels =[]
    print("Dataset is being read -> "+str(testDataFileName)+".csv")
    foo = pd.read_csv(testDataFileName+".csv",iterator=True,chunksize=50000)
    for chunk in foo:
        resultData= pd.concat([resultData,chunk])
        predictedLabels = predictTheCollectedData(chunk,model)
        for val in predictedLabels:
            resultLabels.append(val)
        


    index =0
    while index < len(resultLabels):
        resultLabels[index] = le_name_mapping[int(resultLabels[index])]
        index = index +1


    print(resultLabels)    
    #print(resultLabels)
    resultData.insert(len(resultData.columns),"Guess",resultLabels)
    resultData.to_csv(testDataFileName + "_predicted.csv")
    print("Results has been saved")
    print(resultData)
    exit()

####