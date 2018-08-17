import json
import requests
from requests import HTTPError
import base64
import re


#scan the request and make a query based on the IP, domain, url
misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', "ip-src", "ip-dst", "md5", "sha1", "sha256", "sha512","url"],
                  'output': ['domain', "ip-src", "ip-dst", "text", "md5", "sha1", "sha256", "sha512", "url",
                             "authentihash", "filename"]
                  }

#Cysiv Internal Threat Intelligence server
moduleinfo = {'version': '0.1', 'author': 'Virendra Bisht',
              'description': 'Query Cysiv Threat Intelligence Server',
              'module-type': ['expansion', 'hover']}

# config fields that your code expects from the site admin
moduleconfig = ['apikey', "event_limit"]
limit = 5  # Default
comment = '%s: Enriched via Threat Intelligence Server'

enrich_server_url = "https://arango-connector-arango.dev.c4intel.com"


#Common validation check
def valid_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))

def valid_domain(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]     # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def check_validurl(url):
    """
    This function ensure the url has valid schema before making a query
    :param url:
    :return:
    """
    regex = re.compile(r'^(?:http|ftp)s?://')                   # http:// or https://
    match = re.findall(regex, url)
    for pattern in match:
        if len(pattern) == 0:
            return False
        else:
            return True

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
def getHash(hash, key,hash_type):
    """
    Check the record in Threat Datatbase
    :param hash: File hash
    :param key: API key
    :param hash_type: hash_type md5, sha1 or sha256
    :return:
    """
    enrichment_url = enrich_server_url + "/" +hash_type +"/"
    #req = requests.get("https://www.virustotal.com/vtapi/v2/file/report",params={"allinfo": 1, "apikey": key, 'resource': hash})


    req = requests.get(enrichment_url)
    try:
        req.raise_for_status()
        req = req.json()
    except HTTPError as e:
        misperrors['error'] = str(e)
        return misperrors

    if req["response_code"] == 0:
        # Nothing found
        return []

    return getMoreInfo(req, key)

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

  #  if req["response_code"] == 0:
 #     # Nothing found
 #       print("OMG!!! Nothing found")
  #      return []

    if "resolutions" in req:
        for res in req["resolutions"][:limit]:
            toReturn.append({"types": ["domain"], "values": [res["hostname"]], "comment": comment % ip})
            # Pivot from here to find all domain info

    toReturn += getMoreInfo(req, key)
    return toReturn


def getDomain(domain, key,):
    global limit
    toReturn = []
    req = requests.get("https://www.virustotal.com/vtapi/v2/domain/report",
                       params={"domain": domain, "apikey": key})
    try:
        req.raise_for_status()
        req = req.json()
    except HTTPError as e:
        misperrors['error'] = str(e)
        return misperrors

    #if req["response_code"] == 0:
    #    # Nothing found
    #    return []

    if "resolutions" in req:
        for res in req["resolutions"][:limit]:
            toReturn.append({"types": ["ip-dst", "ip-src"], "values": [res["ip_address"]], "comment": comment % domain})

    if "subdomains" in req:
        for subd in req["subdomains"]:
            toReturn.append({"types": ["domain"], "values": [subd], "comment": comment % domain})
    toReturn += getMoreInfo(req, key)
    return toReturn


def findAll(data, keys):
    a = []
    if isinstance(data, dict):
        for key in data.keys():
            if key in keys:
                a.append(data[key])
            else:
                if isinstance(data[key], (dict, list)):
                    a += findAll(data[key], keys)
    if isinstance(data, list):
        for i in data:
            a += findAll(i, keys)

    return a


def getMoreInfo(req, key):
    global limit
    r = []
    # Get all hashes first
    hashes = []
    hashes = findAll(req, ["md5", "sha1", "sha256", "sha512","url","hostname"])
    r.append({"types": ["freetext"], "values": hashes})
    print(r)
    print("################# YOU GOT IT ##########")
    return r



def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
