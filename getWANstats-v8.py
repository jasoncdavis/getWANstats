#!/usr/local/bin/python3.6

"""
getWANstats.py

script for getting the WAN router stats for CiscoLive events.
Uses pySNMP module to do SNMPv3 gets of the IfHCInOctets and IfHCOutOctets objects
Then uses Requests module to push data into InfluxDB
Ensure there is a 'wanstats' database in InfluxDB, or change script to reflect alternate 
database

jadavis@cisco.com

MIT License

Copyright (c) [2017] [Jason C Davis]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


v1	Initial version
v2	Enhanced with command line functionality - able to pass
	-frequency X       time between polls
	-nocapture         prevents push to influxdb - helpful for observing stats without 
	capture
v3  Removed v2 enhancements in favor of scheduler function; Added IPv6 stats
v4	Minor edits
v5	First public release to Github
v6	Rewrites for scheduling and table indicies
v7	jadavis	2018-0124 Added capability to do IPv4/IPv6 ratio calculations and injection to influx
v8	jadavis	2018-0126	Added memory monitoring and test capabilities
"""


from pysnmp.entity.rfc3413.oneliner import cmdgen
from ast import literal_eval
import re
import requests
import schedule
import time
import datetime

debugmode = 0 #if set 1 (true) then script will print debug messages and not upload metrics to influx
influxserver = "localhost"
snmp_dict = {}
url = "http://" + influxserver + ":8086/write"
querystring = {"db":"wanstats"}
headers = {'cache-control': 'no-cache'}


def calcratios():
	global snmp_dict
	ipv4sum = ipv6sum = 0
	for (ipaddress, oid, index) in snmp_dict.keys():
		if debugmode: print(ipaddress, oid, index,' : ',snmp_dict[(ipaddress, oid, index)])
		if re.match('ipv4', index): ipv4sum += int(snmp_dict[(ipaddress, oid, index)])
		if re.match('ipv6', index): ipv6sum += int(snmp_dict[(ipaddress, oid, index)])
	ratio = ipv6sum / ipv4sum * 100
	payload = "ipratio,ipversion=4,metric=octets value=" + str(ipv4sum) + "\nipratio,ipversion=6,metric=octets value=" + str(ipv6sum) + "\nipratio,metric=ratio value=" + str(ratio)
	if debugmode:
		print("IPv4 Sum: {} + IPv6 Sum: {} = Ratio {}".format(ipv4sum, ipv6sum, ratio))
		print("Payload is:\n{}".format(payload))
	else:
		response = requests.request("POST", url, data=payload, headers=headers, params=querystring)

def calcmemratios():
	global snmp_dict
	core1ratio = core2ratio = 0
	hostlist = hostset = []
	payload = ""
	for (ipaddress, oid, index) in snmp_dict.keys():
		hostlist.append(ipaddress)
	if debugmode: print("Duplicated hostlist: {}".format(hostlist))
	hostset = set(hostlist)
	hostlist = list(hostset)
	if debugmode: print("De-duplicated hostlist: {}".format(hostlist))
	
	for host in hostlist:
		memtotal = int(snmp_dict[host,'cempMemPoolHCUsed','7000.1']) + int(snmp_dict[host,'cempMemPoolHCFree','7000.1'])
		memratio = int(snmp_dict[host,'cempMemPoolHCUsed','7000.1']) / memtotal * 100
		if debugmode: print("host: {}  memtotal: {}   memratio: {}".format(host, memtotal, memratio))
		payload += "memratio,host=" + str(host) + ",metric=bytes,oid=cempMemPoolHCFree value=" + snmp_dict[host,'cempMemPoolHCFree','7000.1'] + "\n"
		payload += "memratio,host=" + str(host) + ",metric=bytes,oid=cempMemPoolHCUsed value=" + snmp_dict[host,'cempMemPoolHCUsed','7000.1'] + "\n"
		payload += "memratio,host=" + str(host) + ",metric=ratio value=" + str(memratio) + "\n"
	
	if debugmode:
		print("Payload is:\n{}".format(payload))
	else:
		response = requests.request("POST", url, data=payload, headers=headers, params=querystring)


# Wait for responses or errors
def cbFun(sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
    global snmp_dict
    (authData, transportTarget) = cbCtx
    #print('%s via %s' % (authData, transportTarget))
    #print transportTarget.transportAddr[0]
    if errorIndication:
        print(errorIndication)
        return 1
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1] or '?'
            )
        )
        return 1
    
    for oid, val in varBinds:
        prettyoid = oid.prettyPrint()
        if debugmode: print(prettyoid)
        mibname = prettyoid.split(':')[0]
        oidname = re.match("\:\:(.*?)\.", prettyoid)
        oidname = re.search('(?<=::)\w+', prettyoid)
        oidindex = re.search('(?<=\.).*', prettyoid)
        if debugmode: print("MIB: {} OID: {} INDEX: {}".format(mibname,oidname.group(0),oidindex.group(0)))
        if val is None:
            print(oid.prettyPrint())
        else:
            payload = "snmp,oid=" + oidname.group(0) + ",host=" + transportTarget.transportAddr[0] + ",ifindex=" + oidindex.group(0) + " value=" + val.prettyPrint()
            if debugmode: print(payload)
            snmp_dict[(transportTarget.transportAddr[0], oidname.group(0), oidindex.group(0))] = val.prettyPrint()
            if not debugmode:
            	response = requests.request("POST", url, data=payload, headers=headers, params=querystring)
    #print(snmp_dict)


def dowork():
	global snmp_dict
	timenow = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
	start = datetime.datetime.now()
	print("Started...", timenow)
	cmdGen  = cmdgen.AsynCommandGenerator()

	# Read input file of devices, credentials, MIB objects, indicies, etc
	data = ''
	with open('devicemetrics2.conf', 'r') as inputfile:
		for line in inputfile:
			if not line.startswith("#"):
				data += line.strip()
	
	targets = eval(data)
	
	# Submit GET requests
	for authData, transportTarget, varNames in targets:
		#print(authData, transportTarget, varNames)
		cmdGen.getCmd(authData, transportTarget, varNames,
		# User-space callback function and its context
		(cbFun, (authData, transportTarget)),lookupNames=True, lookupValues=True)
	
	cmdGen.snmpEngine.transportDispatcher.runDispatcher()
	calcratios()
	calcmemratios()
	
	end = datetime.datetime.now()
	elapsed = end - start
	#print(elapsed.seconds,":",elapsed.microseconds) 
	
	#timenow = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
	print("   Done... {0}.{1}sec".format(elapsed.seconds, elapsed.microseconds))
	

schedule.every(10).seconds.do(dowork)

while 1:
	schedule.run_pending()
	time.sleep(1)
	
	