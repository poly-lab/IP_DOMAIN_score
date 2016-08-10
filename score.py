import json
import urllib
import os
import MySQLdb
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
def read_source(source_path):
    sources=open(source_path).readlines()
    print len(sources)
def read_key(key_path):
    lines=open(key_path,"r").readlines()
    print len(lines)
    for line in lines:
        pass

def insert_db(source,result):
    db = MySQLdb.connect(host='localhost', db='ip_domain', user='root', passwd='polydata', port=3306,
                         charset='utf8')
    cursor = db.cursor() 
    insert_sql="insert into domain(domain,result) VALUES ('{0}','{1}')".format(source,result)
     
def control():
    pass
if __name__=="__main__":
    key_path=os.path.join("key","key")
    source_path=os.path.join("source","ip.txt")
    domain='ozgkraa.net'
    apikey='f938cb8607a8d497a789c47c8ad9fda85d92ad2c8bc1cc37b0d0a45cf408e4e2'
    ip='213.159.214.106'
    read_key(key_path)
    read_source(source_path)
    #domain_score(domain, apikey)
    #ip_score(ip, apikey)
    