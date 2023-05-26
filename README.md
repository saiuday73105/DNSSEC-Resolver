# DNSSEC-Resolver

### Description
A custom DNS resolver that supports the DNSSEC (Domain Name System Security Extensions) protocol. The resolver performs the traditional DNS resolution on different domain types (`A`, `NS`, `MX`) and also reports performance metrics such as the query resolution time. To have a secure resolution, the DNS resolver uses the DNSSEC protocol.

### Workflow
![alt text](https://github.com/saiuday73105/DNSSEC-Resolver/blob/main/DNSSEC%20Workflow.png?raw=true)

### Implementation
The explanation of the implementation would be more precise with an example. For the input domain
`“verisign.com.”` the following would be the workflow;

- First, the function `dnssecResolution()` would be called, which splits the input domain into different
zones (i.e., `verisign.com.` into `[‘verisign’, ‘com’, ‘.’]`) and initializes variables with data related to root,
i.e., the zone as `‘.’`, the list of the current servers to be queried with as the 13 roots, etc.
- Then a while loop is started which is broken when we either successfully get a resolved IP address
or if we encounter “DNSSEC verification failed” or “DNSSEC not supported” errors.
- The first time the `getNextServers()` function is called, it is called with the previously initialized data
related to the root.
- Inside the `getNextServers()` function we query each root server for DNSKEY records of the `‘.’` zone.
The response we get from the server is validated. The validation process is as follows,
  - With the root public KSK hash obtained from the iana website which was defined during the
Root Signing Ceremony and trusted, we compare the hash of the public KSK received in response to the DNSKEY query to the root.
  - After matching this, using the RRSet (containing the public KSK and public ZSK), RRSig, and key set in
dictionary format as input to the inbuilt function `dns.dnssec.validate()` in the `dnssec` library we can
verify the RRSet obtained. This verifies our DNSKEY record for authenticity.
- A point to be noted from the above bullets is that even though we have verified the DNSKEY response,
there could be a case that both the KSK and RRSig values were modified by some malicious DNS.
Therefore, we need to build a chain of trust between the current zone with its parent zone. That is why
we have to compare the DS record given by the parent zone with the hash of the public KSK from the
child zone (i.e., in our case DS record from the `‘.’` zone should be compared with the public KSK from the
`‘com.’` zone). Since the DS record for the root was obtained after the Root Signing Ceremony and made
completely transparent and public, we can trust that.
- Now we query the `‘.’` zone for the `‘A’` record of the input domain. From the response, we first validate the
DS record using the new RRSet (containing the DS record of the `‘com.’` zone present with the `‘.’` zone),
RRSig, and the old RRSet (containing the public KSK and ZSK) as input to the dns.dnssec.validate()
function.
- After the verification of the DS record is successfully completed, we collect the DS record and store its
content (i.e., the hashed public KSK of the next zone (i.e., `‘com.’` since we are currently at the `‘.’` zone)).
- Now that we have validated that we have received the data from a trusted server, depending on the
response part we receive from the server we either return the resolved IP (in case we get the answer
section in response), return the list of the next name servers to hit with a query (in case we get the IPs in
additional sec on in response) or call the `getNextServers()` function with the `NS` values obtained from
the authority section to resolve them.
- Like this the process is continued  till the while loop we started is broken.

The “DNSSEC not supported” case arises if at any zone we do not get RRSet, RRSig, or DS record of the child
zone. Apart from this, the “DNSSEC verification failed” case arises when the hash of the public KSK obtained
from the child zone does not match with the DS of the child obtained from the parent zone and also when
are not able to validate the RRSig of DNSKEY or DS record.
