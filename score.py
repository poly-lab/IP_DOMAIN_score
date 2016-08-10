import json
import urllib
def domain_score(domain,apikey):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    parameters = {'domain': domain, 'apikey': apikey}
    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
    response_dict = json.loads(response)
    print response_dict
    
def ip_score(ip,apikey):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip': ip, 'apikey': apikey}
    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
    response_dict = json.loads(response)
    print response_dict

if __name__=="__main__":
    domain='ozgkraa.net'
    apikey='f938cb8607a8d497a789c47c8ad9fda85d92ad2c8bc1cc37b0d0a45cf408e4e2'
    ip='213.159.214.106'
    domain_score(domain, apikey)
    ip_score(ip, apikey)
    