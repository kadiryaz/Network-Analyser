import os
import AI_Module
import time
from threading import Thread
#from  pyflowmeter.sniffer import create_sniffer
import cicflowmeter.sniffer as cf_sniffer


sniffingPeriod = 20 #sec
isSniffing = False


def runCicFLowmeter(ethernet, csvFileName):
    os.system("sudo cicflowmeter -i " + str(ethernet) +" -c "+ str(csvFileName)+".csv")
#def startSniffing(ethernet, csvFileName):
    #global isSniffing
    #sniffingTimerThread = Thread(target=sniffingTimer_Tick, args=(csvFileName,))
    #isSniffing = True
    #sniffingTimerThread.start()
    #cicFlowmeterThread = Thread(target=runCicFLowmeter,args=(ethernet,csvFileName))
    #cicFlowmeterThread.start()
    #app = subprocess.Popen("python3 ./cicflowmeter/src/cicflowmeter/sniffer.py -i " + str(ethernet) +" -c "+ str(csvFileName)+".csv")



def startSniffing(ethernet,csvFileName):
    global isSniffing
    print("Network Sniffing has been started")
    sniffer = cf_sniffer.create_sniffer(
        None,
        ethernet,
        'flow',
        #to_csv = True,
        str(csvFileName) +".csv"
    )
    sniffer.start()
    isSniffing = True
    sniffingTimerThread = Thread(target=sniffingTimer_Tick)
    sniffingTimerThread.start()

    while isSniffing:#sniffingTimer_tick will change this variable
        continue

    sniffer.stop()
    sniffer.join()
    print("Sniffing has finished. Packets are being analysed")
    analyseCsvFile(csvFileName)
    
def stopSniffing():
    global isSniffing
    isSniffing = False

#def killCicFlowMeter(csvFileName):
    #global isSniffing
    #os.system('sudo pkill -9 -f cicflowmeter')
    #isSniffing = False
    #print("Sniffing is stopped. Result is being analysed ...")
    #analyseCsvFile(csvFileName)

def convertPcapToCsv(pcapFileName, csvFileName):
    os.system("sudo cicflowmeter -f " + str(pcapFileName) +" -c "+ str(csvFileName)+".csv")

def sniffingTimer_Tick():
    global sniffingPeriod
    global isSniffing
    sniffingStartTime = time.time()
    while isSniffing:
        statisticsEndTime = time.time()
        elapsedTime = statisticsEndTime-sniffingStartTime
        if  elapsedTime >= sniffingPeriod:
            stopSniffing()

def analyseCsvFile(csvFileName):
    try:
        AI_Module.testDataFileName = csvFileName
        AI_Module.main()
        print(" ************************* ")
    except Exception as ex:
        print(ex)
        



def action_sniff():
    global sniffingPeriod
    period = input("Please Enter a time period(sec) for sniffing(* for default 20 sec)\n")
    csvFile = input("Please Enter a Output File Name Without File ext(Press * for flows.csv)\n")
    ethernetInterface = input("Please Enter the name of your ethernet interface(Press * for eth0)\n")
    if period == "*":
        sniffingPeriod = 20
    else :
        sniffingPeriod = int(period)
    if csvFile == "*":
        csvFile = "flows"
    if ethernetInterface == "*":
        ethernetInterface = "eth0"

    startSniffing(ethernetInterface,csvFile)
        
def action_readFromPcap():
    pcapFile = input("Please Enter a Pcap File Name(Press * for pcapFile.pcap)\n")
    csvFile = input("Please Enter a Output File Name Without File ext(Press * for flows.csv)\n")

    if pcapFile == "*":
        pcapFile = "pcapFile.pcap"
    if csvFile == "*":
        csvFile = "flows"

    convertPcapToCsv(pcapFile,csvFile)
    analyseCsvFile(csvFile)

def action_readFromCsv():
        csvFile = input("Please Enter the Csv File Name Without File ext\n")
        analyseCsvFile(csvFile)



def MainMenu():
    try:
        action = input("1.Start Sniffing\n2.Read From Pcap File\n3.Read From CicFLowmeter (.csv) output\n")
        if action == "1":
            action_sniff()
        elif action == "2":
            action_readFromPcap()   
        elif action == "3":
            action_readFromCsv()    
        else :
            print("Command ("+action+ ") is not exist") 
            MainMenu()  
    except Exception as ex:
        print(ex)
        print(" ************************* ")
        MainMenu()        

MainMenu()
