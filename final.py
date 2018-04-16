import re
import requests
import socket
import ssl
import datetime
from tldextract import extract
import pythonwhois
from bs4 import BeautifulSoup
import subprocess
import whois
from google import search
co=1
file = open('data.txt', 'r') 
urltemp =  file.read()
start = urltemp.find("'") + 1
end = urltemp.find("'", start)
url = urltemp[start:end]
print(url)
gf=1
try:
    r=requests.get(url)
except:
    gf=-1
# URL having IP address in domain

symbol = re.findall(r'(http((s)?)://)((((\d)+).)*)((\w)+)/((\w)+)',url)
if(len(symbol)==0):
 IP_atr=1
else:
  IP_atr=-1
print ( IP_atr)


# URL having long length 

length=len(url)
length_atr=0
if (length>=54 and length<=75):
  length_atr=0
elif (length<54):
  length_atr=1
elif() :
  length_atr=-1
print (length_atr)

#tiny url
tsd, td, tsu = extract(url) 

host = td + '.' + tsu 
try:
    response = requests.get(url)
    furl=response.url
    tsd, td, tsu = extract(furl) 

    fhost = td + '.' + tsu 
    if(host == fhost):
      shortened_atr=1
    else:
      shortened_atr=-1
    print (shortened_atr)
except:
    print(-1)

# URL having @ symbol

symbol=re.findall(r'@',url)
if(len(symbol)==0):
 at_the_rate_symbol=1
else:
 at_the_rate_symbol=-1 
print (at_the_rate_symbol)


# URL having // beyond 7th position

symbol=re.findall(r'http://www.((\w)*)//((\w)*)',url)
symbol1=re.findall(r'https://www.((\w)*)//((\w)*)',url)
if(len(symbol)!=0 and len(symbol1)!=0):
  slash_atr=-1
elif((len(symbol)!=0 and len(symbol1)==0) or (len(symbol)==0 and len(symbol1)!=0)):
  slash_atr=-1
else:
  slash_atr=1
print (slash_atr)


# URL having - attribute

symbol = re.findall(r'http((s)?)://www.((\w)+)-((\w)+).com',url)
if(len(symbol)!=0):
 dash_atr=-1
else:
 dash_atr=1 
print (-1)


#top levelomain
print('tl')
if(url.count('.')<3):
    print(1)
elif(url.count('.')<=4):
    print(0)
else:
    print(-1)


#HTTPs certificate
    
print('https')  
if(re.search('^https',url)):
    containhttps = 1
else:
    containhttps = 0


tsd, td, tsu = extract(url) 

host = td + '.' + tsu 

try:
  hostname = host
  ctx = ssl.create_default_context()
  s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
  s.connect((hostname, 443))
  cert = s.getpeercert()

  # if you will print cert , you will get various information about certificate like issuer,starting date , ending date
  subject = dict(x[0] for x in cert['subject'])
  issued_to = subject['commonName']
  issuer = dict(x[0] for x in cert['issuer'])
  issued_by = issuer['commonName']
  # it contains issuer name, but its data type is in unicode
  issued_by = str(issued_by)
  issued_by = issued_by.split()
  if(issued_by[0] == "Network" or issued_by == "Deutsche"):
    issued_by = issued_by[0] + " " + issued_by[1]
  elif(issued_by[0] == "Google"):
    issued_by = issued_by[0] + " " + issued_by[1] + " " + issued_by[2] 	
  else:
    issued_by = issued_by[0] 
  # changing the data type of issued_by to str
  starting = str(cert['notBefore'])
  # it contains starting date , since its data type is unicode , so converting it to str
  ending = str(cert['notAfter'])
  # it contains ending date , and its data type is str
  words = starting.split()
  syear = words[3]
  # now syear contains starting year , but it is in string format

  words2 = ending.split()
  eyear = words2[3]
  # it contains ending year , but it is in str format
  syear = int(syear)
  eyear = int(eyear)
  # converting both syear and eyear in int format


  duration = eyear - syear
  # duration is the age of certificate in years
 
  issuers = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign','Google Internet Authority']
  if((containhttps == 1) and (issued_by in issuers) and (duration >= 1)):
    print (1)
  elif((containhttps == 1) and (issued_by in issuers)):
    print (0)
  else:
    print (-1) 	
except:
    print(-1)


#domain registration length
print('drl')
domain = host

try:
  w = pythonwhois.get_whois(domain)
  if  'id' not in w:
    print(-1)
  else :

   
    ud = w['updated_date']

    ed = w['expiration_date']

    diff = ed[0] - ud[0]


    comp = datetime.timedelta(365,0,0,0)


    if(diff > comp):
      print (1)
    else:
     print (-1)	
except:
    print(-1)
#favicon
print('fav')
try:
    r=requests.get(url)
    d=r.text
    s=BeautifulSoup(d,"lxml")
    l=[]
    for link in s.find_all('link'):
       l.append(link.get('href'))
    b=" "
    for x in l:
       x=str(x)
       b=x
       c= x.find(".ico")
       if c!=-1:
         break

    tsd, td, tsu = extract(url) 

    ourl = td + '.' + tsu
    tsd, td, tsu = extract(b) 

    favurl = td + '.' + tsu
#print(ourl," ",favurl)
    if(favurl==ourl or favurl=='.'):
       print(1)
    else:
     print(-1)

except:
    print(-1)

#port
print('port')
try:
   subprocess.call('clear', shell=True)


   remoteServer    = tsd + '.' + host
   remoteServerIP  = socket.gethostbyname(remoteServer)
   p=[22,80,443,445]
   st=[10060,0,0,10060]
   i=0
   f=1

   for port in p:  
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        #print(result)
        if result != st[i]:
            f=0
            break
        sock.close()
        i=i+1
   if f:
    print(1)
   else:
    print(-1)
except:
    print(-1)
#https symbol
print('https')
symbol= re.findall(r'https://((\w)*)https((\w)*)',url)
if(len(symbol)==0):
  http_atr=1
else :
  http_atr=-1
print (http_atr)


#request url

print('request')
tsd, td, tsu = extract(url) 

hurl = td + '.' + tsu 
try:
    r=requests.get(url)
    c=0
    t=0
    soup = BeautifulSoup(r.content,'lxml')
    imgs = soup.find_all("img",{ "src":True})
    t+=len(imgs)
    for img in imgs:
      tsd, td, tsu = extract( img['src'])
      lurl = td + '.' + tsu
      if(hurl==lurl or lurl=='.'):
        c+=1
    soup = BeautifulSoup(r.content,'lxml')        
    imgs = soup.find_all("video",{"src":True})
    t+=len(imgs)
    for img in imgs:
      tsd, td, tsu = extract( img['src'])
       #print(img['source'])
      lurl = td + '.' + tsu
      if(hurl==lurl or lurl=='.'):
        c+=1
    ans=1
      #print(c,t)
    if(t==0):
        print(1)
    else :
        ans=c/t
    if(ans>=0.6 and t!=0):
        print(1)
    elif ans>0.3 and t!=0:
        print(0)
    elif t!=0:
        print(-1)

except:
    print(-1)


#a tag request
print('a')
try:
   r= requests.get(url)
   soup=BeautifulSoup(r.content,'lxml')
   tsd, td, tsu = extract(url) 

   hurl = td + '.' + tsu 
   d=0
   t=1
   sor=soup.find_all("a",{"href":True})
   t+=len(sor)
   for link in sor:
       tsd, td, tsu = extract(link['href']) 

       lurl = td + '.' + tsu
        
       if(hurl==lurl or lurl=='.'):
    
        
                    d=d+1
   avg=0
   if(t!=0):
     avg=d/t
     avg=1-avg
   if(avg<.17 and t!=0):
    ans=1
   elif(avg>=.17 and avg<=.81 and t!=0):
    ans=0
   elif(t!=0):
    ans=-1
   print(ans)

except:
    print(-1)
#links in meta etc
print('meta')
try:
    r= requests.get(url)
    soup=BeautifulSoup(r.content,'lxml')
    a=0
    b=0
    c=0
    d=0
    for link in soup.find_all("meta"):
     if(link.get("href")):
        a=a+1
    for link in soup.find_all("link"):
     if(link.get("href")):
        b=b+1
    for link in soup.find_all("script"):
     if(link.get("src")):
        c=c+1
    for link in soup.find_all("a"):
    
     if(link.get("href")):
        d=d+1
    tot=a+b+c+d
    nume=a+b+c
    avg=1
    if(tot!=0):
     avg=float(nume/tot)
    if(avg<.17):
     ans=1
    elif(avg>=.17 and avg<=.81):
     ans=0
    else:
     ans=-1
    print(ans)
except:
    print(-1)




#sfh


print('NA')




#mail send
try:
    r=requests.get(url)
    d=r.text
    s=BeautifulSoup(d,"lxml")
#print(s)
    s=str(s)
    if s.find("mailto:")!=-1:
     print(-1)
    else:
     print(1)

except:
    print(-1)
#abnormal url
try:
    w = pythonwhois.get_whois(host)
    if  'id' not in w:
     print(-1)
    else :
     print(1)
except:
    print(-1)

#redirect url


try:
  response = requests.get(url)
  c=0;
  for resp in response.history:
     #print(resp.url)
     c+=1

  if(c<2):
     print(0)
  elif(c>=2 and c<=4):
     print(0)
  else :
     print(0)

except:
    print(-1)
#status barcustomization
try:
 r=requests.get(url)
 d=r.text
 s=BeautifulSoup(d,"lxml")
 #print(s)
 s=str(s)
 if s.find("location.href")!=-1 or (s.find("onmouseover")!=-1 and s.find("window.status")!=-1):
    print(-1)
 else:
    print(1)

except:
    print(-1)
#diabling right click
try:
 r=requests.get(url)
 d=r.text
 s=BeautifulSoup(d,"lxml")
 #print(s)
 s=str(s)
 if s.find("oncontextmenu")!=-1 or s.find(".button==2")!=-1 or s.find(".mousedown==3")!=-1:
    print(-1)
 else:
    print(1)
except:
    print(-1)
#popup window
try:
 r=requests.get(url)
 d=r.text
 s=BeautifulSoup(d,"lxml")
 #print(s)
 s=str(s)
 #print(s)
 if s.find("prompt")!=-1 :
    print(-1)
 else:
    print(1)
except:
    print(-1)
#iframe tags
try:
 r=requests.get(url)
 s=str(s)
 s=BeautifulSoup(r.content,'lxml')
 if(len(s.find_all('iframe'))!=0):
    print(-1)

 else:
    print(1)

except:
    print(-1)
#age of domsin


w=0
try:
    w=whois.whois(host)
    #print(w) 
    w=w.creation_date

    if (w==None):
     print(-1)
    else:
     c=w

     n=datetime.datetime.now()
     end_date = n
     start_date = c
     ans = abs((end_date - start_date).days)
     if (ans>180):
      print(1)
     else:
      print(-1)
except:
    print(-1)


#name servers

w=0
try:
   w=whois.whois(host)
   w=w.name_servers
   if(len(w)>0):
    print(1)
   else:
    print(-1) 
except:
   print(-1)


#website traffic


print(-1)


#googlepagerank

try:
    rurl="https://pr.domaineye.com/pr/"+ tsd+'.'+host
    r= requests.get(rurl)
    soup=BeautifulSoup(r.content,'lxml')
    s=soup.find_all('em')
    b=s[1]
    b=str(b)
    b=b[4:6]
    if(b[1]!='0'):
     b=b[0]
    b=int(b)
    #print(b)
    if(b>2):
     print(1)
    else:
     print(-1)
except:
    print(-1)


#google search
c=0
query = "info" + url
for j in search(query, tld="co.in", num=10, stop=1, pause=0):
    tsd, td, tsu = extract(j) 

    hurl = td + '.' + tsu
    if(hurl==host):
        c+=1
if(c!=0):
    print(1)
else :
    print(1)
#no of links pointing to page

print('NA')





#phistank database

print('NA')

