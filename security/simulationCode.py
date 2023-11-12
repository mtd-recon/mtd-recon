import random

scanningRate = 10
addressSpace= 1000
interval = 10
simulationCount = 100
simulationCountForHistogram = 100

def findIP(addressSpace, intervalCount, scanningRatePerInterval):
    intervalCounter = 1
    while intervalCounter < intervalCount+1:
        min = (intervalCounter-1)* scanningRatePerInterval
        max = intervalCounter * scanningRatePerInterval
        scanIP = random.randint(1, addressSpace)
        #:print("Random: ", scanIP, " interval:", intervalCounter)
        if (scanIP > min) and (scanIP < max+1):
            return intervalCounter
        intervalCounter +=1
    return -1

def simulateScanning(scanningRate, addressSpace, interval, simulationCount):
    scanningRatePerInterval = scanningRate * interval
    intervalCount = addressSpace /scanningRatePerInterval
    simulationCounter = 0
    sum = 0
    passCounters=[0 for x in range(10)]
    
    while simulationCounter < simulationCount:
        iteration = 0
        count = findIP(addressSpace, intervalCount, scanningRatePerInterval)
        deneme = True
        while count ==-1: #IP not found in the scan
            iteration += 1
            count = findIP(addressSpace, intervalCount, scanningRatePerInterval)
        sum += count+ (iteration * intervalCount)
        if iteration > 9: #check only for first 10 scan attempt
            iteration=9
        passCounters[iteration] +=1
        simulationCounter += 1
    averageCount = sum/simulationCount
    averageScan = averageCount * scanningRatePerInterval
    #print("Sum:", sum, " average count: ", averageCount, " average scan count: ", averageScan)
    #print("Average scan count: ", averageScan)
    #print("More pass:", passCounters)
    return passCounters

def generateHistogram():
    passCounters=[0 for x in range(10)] #how many pass needed for a successfull scan
    simulationCounter = 0
    while simulationCounter < simulationCountForHistogram:
        counters = simulateScanning(scanningRate, addressSpace, interval, simulationCount)
        passCounters = [x + y for x, y in zip(passCounters, counters)]
        simulationCounter += 1
    avgPassCounters = [x / simulationCountForHistogram for x in passCounters]
    print("Avg pass counters:", avgPassCounters)

def simulation():
    scanningRates = [1, 5, 10, 25]
    addressSpaces=[1000, 2000, 5000]
    intervals = [5, 10, 20]
    for addressSpaceVar in addressSpaces:
        for scanningRateVar in scanningRates:
            for intervalVar in intervals:
                scanningRate = scanningRateVar
                addressSpace=addressSpaceVar
                interval = intervalVar
                print("Address space: ", addressSpace, " scanningRate: ", scanningRate, " interval: ", interval)
                generateHistogram()

simulation()
