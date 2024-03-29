import os
print("""
      _ _   _                       
     | | \ | |                      
     | |  \| |_ __ ___   __ _ _ __  
 _   | | . ` | '_ ` _ \ / _` | '_ \ 
| |__| | |\  | | | | | | (_| | |_) |
 \____/|_| \_|_| |_| |_|\__,_| .__/ 
                             | |    
                             |_|    
JNmap 
Tools Scanning Network With Nmap
""")
print("-----------------------------")
print("Nmap Scan")
print("[1] Nmap All Scan")
print("[2] Nmap Eternal Blue Vulner")
print("[3] Nmap Heartbleed Vulner")
print("[4] Nmap Subnet Scan")
print("[5] Nmap Top Ports Scan")
print("[6] Nmap SSH brute-force")
print("[7] Nmap CVE Detection")
print("[8] Nmap Launching DOS")
print("[9] Nmap Slowloris Check")
print("[10] Nmap Check Poodle")
print("[11] Nmap Check LDAP")
print("[12] Nmap DNS Recursion")
print("[13] EXIT")

option = int(input("Enter number : \n"))


if option == 1:
    os.system("""echo -n " Target : "
read Ip
echo -n " Scan Name :"
read Name
sudo -S nmap -A -v -O -T4 $Ip -oN ~/JNmapReports/$Name
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")

elif option == 2:
    os.system("""echo -n " Target : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap -Pn -p445 --script smb-vuln-ms17-010 $Ip >> ~/JNmapReports/$Name.txt
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")

elif option == 3:
    os.system("""echo -n " Target : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap -Pn -p 443 --script ssl-heartbleed $Ip >> ~/JNmapReports/$Name.txt
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")

elif option == 4:
    os.system("""echo -n " Target with subnet (example <IP>/24) : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap -v $Ip -oN ~/JNmapReports/$Name
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")


if option == 5:
    os.system("""echo -n " Target : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap -F $Ip -oN ~/JNmapReports/$Name
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]""")

elif option == 6:
    os.system("""echo -n " Target : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst \
  --script-args ssh-brute.timeout=4s $Ip -oN ~/JNmapReports/$Name
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")

elif option == 7:
    os.system("""echo -n " Target : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap -Pn --script vuln $Ip -oN ~/JNmapReports/$Name
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")


elif option == 8:
    os.system("""echo -n " Target : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap $Ip -max-parallelism 800 -Pn --script http-slowloris --script-args http-slowloris.runforever=true -oN ~/JNmapReports/$Name
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")

elif option == 9:
    os.system("""echo -n " Target : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap --script http-slowloris-check $Ip -oN ~/JNmapReports/$Name
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")

elif option == 10:
    os.system("""echo -n " Target : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap -sV --version-light --script ssl-poodle -p 443 $Ip -oN ~/JNmapReports/$Name
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")

elif option == 11:
    os.system("""echo -n " Target : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap -p 389 --script ldap-rootdse $Ip -oN ~/JNmapReports/$Name
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")

elif option == 12:
    os.system("""echo -n " Target : "
read Ip
echo -n " Name for Scan : "
read Name
sudo -S nmap -Pn -sU -p 53 --script=dns-recursion $Ip -oN ~/JNmapReports/$Name
echo "[+] Scan Complete [+]
[*] Check Reports Dir. for Results [*]"
""")

elif option == 13:
 exit;
