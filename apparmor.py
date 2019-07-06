# linux firewall based on apparmor
# very experimental, very alpha
# https://pythonprogramminglanguage.com
import glob
import os
import subprocess
import json
import os

def profiles():
    result = subprocess.run(['apparmor_status', '--json'], stdout=subprocess.PIPE)
    data = result.stdout.decode('utf-8')
    aa_status = json.loads(data)
    return aa_status

def unconfined():
    result = subprocess.run(['aa-unconfined', '--paranoid'], stdout=subprocess.PIPE)
    data = result.stdout.decode('utf-8')
    lines = data.split("\n")
    apps = []
    for line in lines:
        app = line.split(" ")
        if len(app) > 1:
            apps.append( (app[0],app[1]) )
        
    return apps

def complain(profile):
    os.system("sudo aa-complain " + profile)
    
def enforce(profile):
    os.system("sudo aa-enforce  " + profile)

def disable(profile):
    os.system("sudo ln -s " + profile + " /etc/apparmor.d/disable/")
    

def apparmor_internet():
    pfiles = glob.glob("/etc/apparmor.d/*")
    apps = []
    for profile in pfiles:
        #print(profile)

        if "~" not in profile:
            if os.path.isfile(profile):
                if 'deny network inet' in open(profile).read() and "#deny network" not in open(profile).read():
                    print("blocked ", profile)
                    apps.append( (profile,"block") )
                else:
                    print("allowed ", profile)
                    apps.append( (profile, "allow") )
                    #deny network inet,
                    #deny network inet6,
                    #deny network raw,
    return apps

def apparmor_block_inet(profile):
    print(profile)
    complain(profile)

    if "deny network inet" not in open(profile).read():
        with open(profile, "a") as myfile:
            # get filename from profile
            #myfile.write("appended text")
            filename = profile.replace("/etc/apparmor.d/","")
            filename = filename.replace(".","/")
            print(filename)
            
            # add to end of file

            # remove last character }
            with open(profile, 'rb+') as filehandle:
                filehandle.seek(-3, os.SEEK_END)
                filehandle.truncate()

            # add block internet             
            myfile.write("\n  deny network inet,\n")
            myfile.write("  deny network inet6,\n")
            myfile.write("  deny network raw,\n")
            myfile.write("  audit deny network,\n")
            myfile.write("  audit deny network inet stream,\n")
            myfile.write("  deny network inet6 stream,\n")
            myfile.write("  deny @{PROC}/[0-9]*/net/if_inet6 r,\n")
            myfile.write("  deny @{PROC}/[0-9]*/net/ipv6_route r,\n")
            myfile.write("  deny capability net_raw,\n")
            myfile.write("}\n")            

    enforce(profile)
    
apps = apparmor_internet()
for app in apps:
    print(app)
    
apparmor_block_inet("/etc/apparmor.d/usr.bin.firefox")
