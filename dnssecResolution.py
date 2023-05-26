import dns.dnssec
import dns.message
import dns.query
import dns.rdatatype
import sys
import time
import datetime

resolutionType = 'A'
# Obtained from https://www.iana.org/domains/root/servers
roots = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13',
         '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', 
         '192.36.148.17', '192.58.128.30', '193.0.14.129','199.7.83.42','202.12.27.33']

# Obtained from https://data.iana.org/root-anchors/root-anchors.xml
rootDSList = ['20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D', '19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5']
rootHashingAlgo = 'sha256'
preRootDomain = '.'

# A function to validate public KSK as well as the RRSET from the 'DNSKEY' query response
def validateDNSKEY(zone, server, zoneKSKHash):
  query = dns.message.make_query(zone, 'DNSKEY', want_dnssec=True)
  response  = dns.query.udp(query, server)
  currKSK = None
  currZSK = None
  rrSet = None
  rrSig = None
  verificationSuccess = True
  for item in response.answer:                  # Exracting pubZSK, pubKSK, RRSET and RRSIG from response.answer for DNSKEY query to the zone server
    if(item.rdtype == dns.rdatatype.DNSKEY):
      rrSet = item
      for element in item:
        if(element.flags == 256): # Flag 256 is for ZSK
          currZSK = element
        if(element.flags == 257): # Flag 257 is for KSK
          currKSK = element
        if(str(element.algorithm) == "Algorithm.RSASHA256" or str(element.algorithm) == "Algorithm.ECDSAP256SHA256"):
          hashingAlgo = "sha256"
        if(str(element.algorithm) == "Algorithm.RSASHA1" or str(element.algorithm) == "Algorithm.RSASHA1NSEC3SHA1" or str(element.algorithm) == "Algorithm.DSA" or str(element.algorithm) == "Algorithm.DSANSEC3SHA1"):
          hashingAlgo = "sha1"
        if(str(element.algorithm) == "Algorithm.ECDSAP384SHA384"):
          hashingAlgo = "sha384"
        if(str(element.algorithm) != "Algorithm.RSASHA1" and str(element.algorithm) != "Algorithm.RSASHA256" and str(element.algorithm) != "Algorithm.ECDSAP256SHA256" and str(element.algorithm) != "Algorithm.ECDSAP384SHA384") and str(element.algorithm) == "Algorithm.RSASHA1NSEC3SHA1" and str(element.algorithm) == "Algorithm.DSA" and str(element.algorithm) == "Algorithm.DSANSEC3SHA1":
          print("DNSSEC not supported") # The dnspython library currently only supports the above 3 hashing algorithms
          return False, verificationSuccess, rrSet

    if(item.rdtype == dns.rdatatype.RRSIG):
      rrSig = item

  if (list(response.to_text().split('\n'))[2] != 'rcode REFUSED') and not (rrSig or rrSet or currKSK):
    print("DNSSEC not supported")
    return False, verificationSuccess, rrSet
  
  if (list(response.to_text().split('\n'))[2] == 'rcode REFUSED') and not (rrSig or rrSet or currKSK):
    pass
  else:
    hashedKSK = str(dns.dnssec.make_ds(zone, currKSK, hashingAlgo)) # Creating the hash of public KSK obtained in DNSKEY response
    ispubKSKVerified = False
    for hash in zoneKSKHash:
      if(hash.lower() == hashedKSK):  # Comparing if the hash of the KSK obtained in DNSKEY response is same as DS record of the zone server
        ispubKSKVerified = True
    if not ispubKSKVerified:
      print("DNSSEC verification failed")
      verificationSuccess = False
      return False, verificationSuccess, rrSet
    try:
      dns.dnssec.validate(rrSet, rrSig, {dns.name.from_text(zone): rrSet}) # Validation of DNSKEY RRSIG
    except dns.dnssec.ValidationFailure:  # On failure to validate the DNSKEY RRSIG by the above function this exception is raised
      print("DNSSEC verification failed")
      verificationSuccess = False
      return False, verificationSuccess, rrSet
  return True, verificationSuccess, rrSet


def getNextServers(inputDomain, zone, currServersList, zoneKSKHash, hashingAlgo):
  for server in currServersList:
    validatedServer, verificationSuccess, dnskeyRRSet = validateDNSKEY(zone, server, zoneKSKHash)
    if(not validatedServer):  # If the validateDNSKEY function returns False then the server cannot be validate and hence we return without doing anything
      return True, [], [], '', 0
    
    # If we have arrived here, it means that the DNSKEY server response has been validated
    query = dns.message.make_query(inputDomain, 'A', want_dnssec=True)
    response  = dns.query.udp(query, server)

    rrSet = None
    rrSig = None
    
    # Parsing the authority section of response to get the DS record (RRSET) and RRSIG of the DS record
    for item in response.authority:
      if(item.rdtype == dns.rdatatype.DS):
        rrSet = item
        nextZoneKSKHash = [str(item[0])]
      if(item.rdtype == dns.rdatatype.RRSIG):
        rrSig = item
    
    isDNSSECSupported = True

    for item in response.authority:
      if(item.rdtype == dns.rdatatype.NSEC3):
        isDNSSECSupported = False
  
    if(not isDNSSECSupported):
      print("DNSSEC not supported")
      return True, [], [], '', 0
    
    try:  # Here we validate the integrity of the response from the second query using the public ZSK we obtained in the previous query
      if(rrSet and rrSig and zone and dnskeyRRSet):
        dns.dnssec.validate(rrSet, rrSig, {dns.name.from_text(zone): dnskeyRRSet})
      else:
        pass
    except dns.dnssec.ValidationFailure:
      print("DNSSec verification failed") # On failure to validate the DS record RRSIG by the above function this exception is raised
    nextServersList = []
    result = []
    
    # After validating the authenticity and integrity of the response, now parsing the response
    # Handling the answer section of response
    if(response.answer):
      for item in str(response.answer[0]).split('\n'):
        if(item.split(' ')[3] == resolutionType):
          result.append(item.split(' ')[4])
      if result:
        return True, result, [], '', response

      for item in response.answer:
        if(str(item).split(' ')[3] == 'CNAME'): # We again continue to resolve the CNAME to get the IP address
          result, respSize = dnssecResolution(item.split(' ')[4])
      if result:
        return True, result, [], '', response

    # Handling the additional section of response
    if(response.additional):
      for item in response.additional:
        if(str(item).split(' ')[3] == 'A'):
          nextServersList.append(str(item[0]))
      if nextServersList:
        return False, nextServersList, nextZoneKSKHash, hashingAlgo, 0

    # Handling the authority section of response
    if(response.authority):
      for item in str(response.authority[0]).split('\n'):

        if(item.split(' ')[3] == 'NS'): # If we come across name server, we continue to resolve it and then call getNextServers to get the result
          resolvedNS, respSize = dnssecResolution(item.split(' ')[4])
        try:  
          ans, res, nextZoneKSKHash, hashingAlgo, resp = getNextServers(inputDomain, zone, resolvedNS, zoneKSKHash, hashingAlgo)
          if res:
            return ans, res, nextZoneKSKHash, hashingAlgo, resp
        except:
          return True, [], [], '', 0


def dnssecResolution(inputDomain):
  inputDomain = inputDomain.rstrip('.')
  dnsHierarchyList = inputDomain.split('.')
  dnsHierarchyList.append('.')
  answer = False
  zone = dnsHierarchyList.pop()
  currServersList = roots
  zoneKSKHash = rootDSList
  hashingAlgo = rootHashingAlgo
  tempFlag = True
  while not answer: # Till we either get our input domain's response in answer section or DNSSEC verification or not supported error we continue to loop
    answer, nextServersList, nextZoneKSKHash, hashingAlgo, finalResp = getNextServers(inputDomain, zone, currServersList, zoneKSKHash, hashingAlgo)
    currServersList = nextServersList
    zoneKSKHash = nextZoneKSKHash
    if len(dnsHierarchyList) != 0:
      if tempFlag:
        zone = zone.rstrip('.')
        tempFlag = False
      zone = dnsHierarchyList.pop() + '.' + zone
    else:
      zone = inputDomain + '.'
  respSize = sys.getsizeof(finalResp)
  return nextServersList, respSize

# A function to print output similar to dig tool
def digLikeOutput(inputDomain, resolutionType, resolutionTime, resolvedIP, respSize):
  if(resolvedIP):
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
  else:
    print("Query time: ", round(resolutionTime), "msec")


inputDomain = str(sys.argv[1])
startTime = time.time()
inputDomain = inputDomain.rstrip('.')
inputDomain = inputDomain + '.'   # Converting the input 'domain' into 'domain.' format for easier parsing
try:
  resolvedIP, respSize = dnssecResolution(inputDomain)
except:
  resolvedIP = []
  respSize = 0
  pass
endTime = time.time()
resolutionTime = (endTime - startTime) * 1000
digLikeOutput(inputDomain, 'A', resolutionTime, resolvedIP, respSize)