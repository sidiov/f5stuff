#Python 3.11
#pip install requests
#pip install argparse
#pip install ipadress
import sys
import getpass
import base64
import argparse
import requests
import ipaddress
from requests.auth import HTTPBasicAuth
from urllib.parse import urlsplit, urlunsplit
import json
import os.path
from datetime import datetime

####Vars**********
#we should define version for REST
f5version = "?ver=17.0.0"
bigips = None
ip = None
DEBUG = False
FILE = None

#this disables warnings on the big-ip management cert (ie self-signed/expired)
requests.packages.urllib3.disable_warnings() 

####functions***********
#log if debug set
def dlog(msg):
    if DEBUG:
        print(msg)
    return

def outMsg(FILE, msg):
    if FILE is None:
        print(msg)
    else:
        with open(FILE, mode='a', encoding="utf-8") as f:
            f.write(f"{msg}\n")
    return

#create basic auth token
def aToken(username, password):
    bAuth = base64.b64encode(bytes(f"{username}:{password}", 'utf-8'))
    bAuth = bAuth.decode("utf-8")
    bHead = f"Basic {bAuth}"
    header = {"Authorization" : bHead}
    return header

#remove the query from url (easier to build)
def url_clean(url):
  # Split the URL into its components
  # url_parts.scheme, .netloc, .path, 
  url_parts = urlsplit(url)

  return f"{url_parts.path}"

#convert object names for api url format
def urlApiName(object):
  new_name = object.replace('/','~') 
  return new_name

def getF5Url(host, uri):
    response = requests.get(f"https://{host}{uri}{f5version}", verify=False, headers=header)
    dlog(f"{uri} => {response}")
    return response.json()

#validate a string as IP and handle the ValueError
def validate_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

#primary function to grab and return cert info
def getAllCerts(bigip):
    #Validate the bigip responds
    ipok = None
    try:
        ipok = requests.get(f"https://{bigip}/mgmt/tm/sys/version?$select=Version,Build", verify=False, headers=header)
    except requests.exceptions.RequestException as e:  
        dlog(e)
        return
    
    if ipok.status_code != 200:
        dlog(f"{bigip} status not OK: {ipok.status_code}")
        return

    #jsonIpok = ipok.json()

    #Get the Virtuals
    jsonResponse = getF5Url(bigip, "/mgmt/tm/ltm/virtual/")

    #iterate the Virtuals
    for virtual in jsonResponse['items']:
        profileUrl_l = url_clean(virtual['profilesReference']['link'])
        profileUrl = profileUrl_l + ("/stats")
        dlog(f"profile URL: {profileUrl}")

        #Request the profile stats (stats shows the TYPE, whereas the profile list does not)
        profile_jsonResponse = getF5Url(bigip, profileUrl)
        
        #iterate profile key:value pairs
        if 'entries' in profile_jsonResponse:
            for profile_key, profile_value in profile_jsonResponse['entries'].items():
                nested_stats = profile_value.get("nestedStats", {})
                entries = nested_stats.get("entries", {})
                
                type_id = entries.get("typeId", {}).get("description", "")
                tm_name = entries.get("tmName", {}).get("description", "")
                dlog(f"name: {tm_name}  ==>> type: {type_id}")
                
                # Check if typeId contains "ssl"
                if "ssl" in type_id:
                    tm_name = entries.get("tmName", {}).get("description", "")
                    dlog(f" >Profile: {tm_name}, type: {type_id}")
                    profileUrl = url_clean(tm_name)
                    profileUrl = urlApiName(profileUrl)
                    #default sslUrl for scope
                    sslUrl = None

                    #get client vs server SSL profiles for correct URI
                    if "client-ssl" in type_id:
                        sslUrl = f"/mgmt/tm/ltm/profile/client-ssl/{profileUrl}"
                    elif "server-ssl" in type_id:
                        sslUrl = f"/mgmt/tm/ltm/profile/server-ssl/{profileUrl}"
                    else:
                        #if we didnt get sslUrl set for some reason, break us out of loop
                        break
                    
                    #request the SSL profile
                    jsonSSL = getF5Url(bigip, sslUrl)
                    
                    #find the cert in use by the profile
                    if jsonSSL["cert"] != "none":
                        certName = jsonSSL["cert"]
                        certName = urlApiName(certName)
                            
                        #request the cert object
                        certUrl = f"/mgmt/tm/sys/file/ssl-cert/{certName}"
                        jsonCert = getF5Url(bigip,certUrl)

                        #get the date the cert expires
                        certDate = datetime.fromtimestamp(jsonCert['expirationDate'])
                        currentTime = datetime.now()

                        if certDate > currentTime:
                            tDiff = abs((certDate - currentTime).days)
                            #dlog(f"{tDiff} days until expiration.")
                        elif certDate <= currentTime:
                            tDiff = "EXPIRED"
                            #dlog("EXPIRED")
                    else:
                        #if no cert in profile, there is no cert date (prevents carrying previous date)
                        certDate = "none"
                        tDiff = "none"

                    #print the row: Virtual, SSL profile, SSL cert, expiration Date, Days until exp. 
                    outMsg(FILE, f"{bigip}, {virtual['name']}, {tm_name}, {jsonSSL['cert']}, {certDate}, {tDiff}")


####Main***********
argParser = argparse.ArgumentParser()
argParser.add_argument("-b", "--bigip", type=str, help="BIG-IP host")
argParser.add_argument("-u", "--username", type=str, help="BIG-IP user")
argParser.add_argument("-p", "--password", type=str, help="BIG-IP pass")
argParser.add_argument("-f", "--file", type=str, help="BIG-IP list in a file")
argParser.add_argument("-d", "--diffpass", action='store_true', help="Prompt for different password per BIG-IP in list file")
argParser.add_argument("-o", "--outputfile", type=str, help="Output to csv file")

args = argParser.parse_args()
print("args=%s" % args)

if args.file is None and args.diffpass is True:
    print("You must use --file <filename> to use --diffpass.")
    sys.exit()
elif args.file is None:
    pass
else:
    try:
       with open(args.file) as file:
          bigips = [line.rstrip() for line in file]
    except IOError:
       print(f"Could not read file: {args.file}")          

if args.bigip is None and args.file is None:
    print("Device IP or name: ", end="")
    ip = input()
elif args.bigip is not None and args.file is not None:
    print("Use either -b or -f not both.")
    sys.exit()
else:
    ip = args.bigip

if args.username is None:
    print("Username: ", end="")
    username = input()
else:
    username = args.username

if args.password is None and args.diffpass is False:
    password = getpass.getpass()
else:
    password = args.password

if args.outputfile is not None:
    FILE = args.outputfile
    with open(FILE, mode='w', encoding="utf-8") as f:
            f.write("")

if args.diffpass is False:
    #create the basic auth token
    header = aToken(username, password)

#Print the CSV columns
outMsg(FILE, "BIG-IP, Virtual, Profile, Cert, Exp Date, Days Until Exp")

#loop the IPs if using file
if bigips is not None:
    dlog(f"Big-IP list: {bigips}")
    for bigip in bigips:
        if args.diffpass is True:
            #get password for each entry
            if args.outputfile is None:
                print("WARNING: Consider using --outputfile <filename> / -o <filename> for cleaner output when using -d.")
            
            print(f"BIG-IP: {bigip}")
            password = getpass.getpass()

        header = aToken(username, password)
        #loop all the bigip entries
        if validate_ip(bigip):
            getAllCerts(bigip)
        else:
            print(f"Bad IP in file: {bigip}")
elif ip is not None:
    dlog(f"Big-IP single: {ip}")
    if validate_ip(ip):
        getAllCerts(ip)
    else:
        print("IP not valid.")
else:
    print("No BIG-IP found.")