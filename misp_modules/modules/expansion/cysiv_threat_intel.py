import json
import requests
from requests import HTTPError
import re

#scan the request and make a query based on the IP, domain, url
misperrors = {'error': 'Error'}
mispattributes = {
                  'input': ['hostname', 'domain', "ip-src", "ip-dst", "md5", "sha1", "sha256", "sha512","url"],
                  'output': ['domain', "ip-src", "ip-dst", "text", "md5", "sha1", "sha256", "sha512", "url", "filename"]
                  }

#Cysiv Internal Threat Intelligence server
moduleinfo = {'version': '0.1', 'author': 'Virendra Bisht',
              'description': 'A Query to Cysiv Threat Intelligence Server',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ['apikey', "event_limit"]
limit = 5      # Default
comment = '%s: Enriched via Threat Intelligence Server'

enrich_server_url = "https://arango-connector-arango.dev.c4intel.com"

#checkIf hashes valid

CheckValidHash = { "md5": re.compile('\b[a-z0-9a-f0-9]{32}\b'),
                   "sha1": re.compile('\b[a-z0-9a-f0-9]{40}\b'),
                   "sha256": re.compile('\b[a-z0-9a-f0-9]{64}\b')
                 }


def check_validurl(url):
    """
    This function ensure the url has valid schema before making a query
    :param url:
    :return:
    """
    regex = re.compile(r'^(?:http|ftp)s?://')
    match = re.findall(regex, url)
    for pattern in match:
        if len(pattern) == 0:
            return False
        else:
            return True


#Ip validation check
def valid_ip(ip):
    """
    Checks the IP it is valid before submitting to MISP
    :param ip:
    :return:
    """
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))

def valid_domain(hostname):
    """
    Check domain length is greater than 255 bytes
    Checks each octect
    :param hostname:
    :return:
    """
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]     # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def getMoreInfo(req):
    #{'values': [u'6b936701cb256ffe121a8a71261b95a778ba41d24e73e2005e14991740cf84ea'], 'types': ['freetext']}
    """
    check the the response from Threat intel and parse url, ip, hashes and domain and return
    as list with pairing each parse value with type
    :param req:
    :return:
    """
    global limit


    mispattr = []

    if "data" in req:
        test = req['data'][0]
        for key, value in test.items():
            if isinstance(value, dict):
                for key, value in value.items():
                    if isinstance(value, list):
                        for items in value:
                            if isinstance(items, dict):
                                for key, value in items.items():
                                    if key == "sha256":
                                        #sha256
                                        mispattr.append({"types": ["freetext"], "values": value})

                                    # elif key == "sha1":
                                    #     mispattr.append({"types": ["freetext"], "values": value})
                                    #
                                    # elif key == "md5":
                                    #     mispattr.append({"types": ["freetext"], "values": value})
                                    #
                                    # elif key == "hostname":
                                    #     if valid_domain(value):
                                    #         mispattr.append({"types": ["freetext"],"values": value})
                                    #
                                    # elif key == "url":
                                    #     if check_validurl(value):
                                    #         mispattr.append({"types": ["freetext"], "values": value})
                                    #
                                    # elif key == "ip":
                                    #     if valid_ip(value):
                                    #         mispattr.append({"types": ["ip-dst","ip-src"], "values": value})

    print(mispattr)
    return mispattr

#Defining the handler
def handler(q=False):
    """
    Handler is the function for the misp-module template
    :param q:
    :return:
    """
    global limit
    if q is False:
        return False

    q = json.loads(q)

    key = q["config"]["apikey"]
    limit = int(q["config"].get("event_limit", 5))
    #url = q["config"]["url"]

    r = {"results": []}

    if "ip-src" in q:
        if valid_ip(q["ip-src"]):
            #query to the server
            r["results"] += getIP(q["ip-src"], key, "ip")

    if "ip-dst" in q:
        if valid_ip(q["ip-dst"]):
            r["results"] += getIP(q["ip-dst"], key, "ip")

    if "domain" in q:
        r["results"] += getDomain(q["domain"], key, "domain")

    if 'hostname' in q:
        r["results"] += getDomain(q['hostname'], key, "domain")

    if 'md5' in q:
        r["results"] += getHash(q['md5'], key, "md5")
    if 'sha1' in q:
        r["results"] += getHash(q['sha1'], key,"sha1")
    if 'sha256' in q:
        r["results"] += getHash(q['sha256'], key, "sha256")
    if 'sha512' in q:
        r["results"] += getHash(q['sha512'], key, "sha512")

    #Only storing the unique values from the result
    uniq = []
    for res in r["results"]:
        if res not in uniq:
            uniq.append(res)
    r["results"] = uniq
    return r

#This is to get the File hash information
def getHash(hash, key,request_type):
    """
    Check the record in Threat Datatbase
    :param hash: File hash
    :param key: API key
    :param hash_type: hash_type md5, sha1 or sha256
    :return:
    """
    enrichment_url = enrich_server_url + "/" + "api/v1/search/" + request_type+ "/" + hash
    Authorization_header = "Basic " + key
    headers = {'authorization': Authorization_header}


    print("Inside get hash", enrichment_url)

    req = requests.get(enrichment_url, headers=headers, verify=False)

    try:
        req.raise_for_status()
        req = req.json()
        print(req)

    except HTTPError as e:
        misperrors['error'] = str(e)
        return misperrors

    return getMoreInfo(req)

def getIP(ip, key, request_type):
    global limit
    toReturn = []
    #API access to the db is based on the IP address and specific url

    enrichment_url = enrich_server_url + "/" + "api/v1/search/" + request_type + "/" + ip
    Authorization_header = "Basic " + key
    headers = {'authorization':  Authorization_header}

    #req = requests.get(enrichment_url, params={"ip": ip, "apikey": key})
    req = requests.get(enrichment_url, headers=headers, verify=False)

    try:
        req.raise_for_status()
        req = req.json()

    except HTTPError as e:
        misperrors['error'] = str(e)
        return misperrors

    if "resolutions" in req:
        for res in req["resolutions"][:limit]:
            toReturn.append({"types": ["domain"], "values": [res["hostname"]], "comment": comment % ip})
            # Pivot from here to find all domain info

    toReturn += getMoreInfo(req)
    return toReturn


def getDomain(domain, key, request_type):
    global limit
    toReturn = []

    enrichment_url = enrich_server_url + "/" + "api/v1/search/" + request_type+ "/" + domain
    Authorization_header = "Basic " + key
    headers = {'authorization': Authorization_header}
    req = requests.get(enrichment_url, headers=headers, verify=False)

    try:
        req.raise_for_status()
        req = req.json()
    except HTTPError as e:
        misperrors['error'] = str(e)
        return misperrors

    if "resolutions" in req:
        for res in req["resolutions"][:limit]:
            toReturn.append({"types": ["ip-dst", "ip-src"], "values": [res["ip_address"]], "comment": comment % domain})

    if "subdomains" in req:
        for subd in req["subdomains"]:
            toReturn.append({"types": ["domain"], "values": [subd], "comment": comment % domain})
    toReturn += getMoreInfo(req)
    return toReturn

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

getIP("5.5.5.5","Y3lzaXZtaXNwOjdodEFSMlVAY2teQkwyJXo=","ip")