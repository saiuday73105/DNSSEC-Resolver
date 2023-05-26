import dns.query
import dns.message
import dns.rdatatype
import dns.resolver
import sys
import time
import datetime

# Obtained from https://www.iana.org/domains/root/servers
roots = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', 
         '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', 
         '192.36.148.17', '192.58.128.30', '193.0.14.129','199.7.83.42','202.12.27.33']

# A function to compute the next servers for a given input domain, resolution type and list of current zone servers
def getNextServers(inputDomain, resolutionType, currServersList):
    query = dns.message.make_query(inputDomain, resolutionType)
    for server in currServersList:
        response  = dns.query.udp(query, server)
        nextServersList = []

        #### Handling answer part of response
        result = []
        if(response.answer and resolutionType != 'MX'):
            for item in str(response.answer[0]).split('\n'):
                if(item.split(' ')[3] == resolutionType):
                    result.append(item.split(' ')[4])
            if result:
                return True, result, response

            for item in response.answer:
                if(str(item).split(' ')[3] == 'CNAME'): # We again continue to resolve the CNAME to get the IP address
                    result, respSize = mydigTool(str(item).split(' ')[4], 'A')
            if result:
                return True, result, response

        result = []
        if(response.answer and resolutionType == 'MX'):
            for item in str(response.answer[0]).split('\n'):
                if(item.split(' ')[3] == 'MX'):
                    result.append(item.split(' ')[5])
            if result:
                return True, result, response

        #### Handling additional part of response
        if(response.additional):
            for item in response.additional:
                if(str(item).split(' ')[3] == 'A'):
                    nextServersList.append(str(item[0]))
            if nextServersList:
                return False, nextServersList, 0

        #### Handling authority part of response
        if(response.authority):
            for item in str(response.authority[0]).split('\n'):
                if(item.split(' ')[3] == 'SOA'):
                    return True, [], ''

                if(item.split(' ')[3] == 'NS'): # If we come across name server, we continue to resolve it and then call getNextServers to get the result
                    resolvedNS, respSize = mydigTool(item.split(' ')[4], 'A')
                ans, res, resp = getNextServers(inputDomain, resolutionType, resolvedNS)
                if res:
                    return ans, res, resp

def mydigTool(inputDomain, resolutionType):
    currServersList = roots
    inputDomain = inputDomain.rstrip('.')
    answer = False

    answer, nextServersList, finalResp = getNextServers(inputDomain, resolutionType, currServersList) # Getting next name servers list using root related initialzed variables
    currServersList = nextServersList
    while not answer:   # Till we get our input domain's response in answer section we continue to loop
        answer, nextServersList, finalResp = getNextServers(inputDomain, resolutionType, currServersList)
        currServersList = nextServersList
    respSize = sys.getsizeof(finalResp)
    return currServersList, respSize


# A function to print output similar to dig tool
def digLikeOutput(inputDomain, resolutionType, resolutionTime, resolvedIP, respSize):
    print("QUESTION SECTION:")
    print(inputDomain, "        IN  ", resolutionType, "\n")
    print("ANSWER SECTION:")
    if(len(resolvedIP) > 0):
        for i in range(len(resolvedIP) - 1):
            print(inputDomain, "        IN  ", resolutionType, " ", resolvedIP[i])
        print(inputDomain, "        IN  ", resolutionType, " ", resolvedIP[len(resolvedIP) - 1], "\n")
    else:
        print("\n")
    print("Query time: ", round(resolutionTime), "msec")
    print("WHEN: ", datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y'))
    print("MSG SIZE rcvd: ", respSize)


inputDomain = str(sys.argv[1])
resolutionType = str(sys.argv[2])
startTime = time.time()
inputDomain = inputDomain.rstrip('.')
inputDomain = inputDomain + '.'         # Converting the input 'domain' into 'domain.' format for easier parsing
resolvedIP, respSize = mydigTool(inputDomain, resolutionType)
endTime = time.time()
resolutionTime = (endTime - startTime) * 1000
digLikeOutput(inputDomain, resolutionType, resolutionTime, resolvedIP, respSize)