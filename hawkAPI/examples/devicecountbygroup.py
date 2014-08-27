from hawkAPI import hawkAPI2
import os
import string
import sys

#------
# Lets flatten the json response
#------
def traverse(o):
    res = []
    for b in o:
        if b["children"] == False:
           res.append(b["key"])          
        else:
           res.append(b["key"])
           res.extend(traverse(b["children"]))
    return res

#----------------------------------
hawk = hawkAPI2.hawkAPI("iptoserver")
hawk.login("userid","password")
data = hawk.getGroups()
fdata = traverse(data["children"])
fdata.append(".")
toNum = 0
rs = [] 
for i in fdata:
    data = hawk.getResByGroup(i,mtype="IDS")
    if data == "":
       pass
    else:
       for b in data["resource"]:
           if b["resource_name"] in rs:
              pass
           else:
             rs.append(b["resource_name"])              
    print "%s:%s" % (i,len(rs))
    toNum += len(rs)
    rs = []      
print toNum
hawk.logout()
sys.exit(1)

