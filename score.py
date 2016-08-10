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
    return len(sources),sources

def read_key(key_path):
    lines=open(key_path,"r").readlines()
    
    return len(lines),lines

def insert_db(source,result):
    db = MySQLdb.connect(host='localhost', db='ip_domain', user='root', passwd='polydata', port=3306,
                         charset='utf8')
    cursor = db.cursor() 
    insert_sql="insert into domain(domain,result) VALUES ('{0}','{1}')".format(source,result)
    cursor.execute(insert_md5)
    db.commit()
    cursor.close()
    db.close()    
     
def control():
    keynum,keys=read_key(key_path)
    sourcesnum,sources=read_source(source_path)
    md5num=n%(keynum*4)
    foallkey=allkey*4
    starttime=time.time()
    parse(vt.getReport(allmd5[n],foallkey[md5num]),allmd5[n])
    cell=time.time()-starttime

    if int(cell) <=60:
        time.sleep(60-int(cell))

if __name__=="__main__":
    key_path=os.path.join("key","key")
    source_path=os.path.join("source","ip.txt")
    
    
    #domain_score(domain, apikey)
    #ip_score(ip, apikey)
    