import requests
import sys
import json
import logging
import httplib
import time
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email import Encoders
from email.utils import COMMASPACE, formatdate
from datetime import datetime
from datetime import timedelta


class hawkAPI(object):

      def __init__(self,server):
         self.sess = requests.session()
         self.server = server
         self.debugit = "False"
         self.retry = 0
         self.setretry = 5


      def setRetry(self,retry):
          self.setretry = retry

      def debug(self,level=1):
         httplib.HTTPConnection.debuglevel = level 
         logging.basicConfig()
         logging.getLogger().setLevel(logging.DEBUG)
         requests_log = logging.getLogger("requests.packages.urllib3")
         requests_log.setLevel(logging.DEBUG)
         requests_log.propagate = True
         self.debugit = "True"

      def login(self,user,passw):
         data = {"username":user,"password":passw,"secure":"false"}
         url = "https://%s:8080/API/1.1/login" % self.server
         try:
              self.sess.post(url,data,verify=False,allow_redirects=True)
         except requests.exceptions.ConnectionError:
              print "Connection Error during login"
              sys.exit(1)
         except requests.exceptions.Timeout:
              print "Timeout during login"
              sys.exit(1)

      def logout(self):
         url = "https://%s:8080/API/1.1/logout" % self.server
         r = self.sess.get(url,verify=False) 
         return "true"

      def callError(self,a,b):
          raise Exception(a,b)
          sys.exit(1) 
 
      def checkData(self,data):
          if "results" in data:
             return data["results"]
          else:
             return 0

      def doGet(self,data):
         url = "https://%s:8080/API/1.1/%s" % (self.server,data)
         try:
             r = self.sess.get(url,verify=False,stream=True,allow_redirects=True)
             if r.status_code == requests.codes.ok:
                 pass
             else:
                 print "Proper code not returned %s" % r.status_code
                 self.logout()
                 sys.exit(1)
             ndata = ""
             for data in r.iter_content(chunk_size=1024):
                 if data:
                    ndata += data
             if self.debugit == "True":
                 print ndata
                 return ndata
             else:
                 return ndata
         except requests.exceptions.Timeout:
             print "Request Timeout during doGet function"
             sys.exit(1)


      def doPost(self,api,data={}):
          if self.retry < self.setretry:
             bdata = self.doTest(api,data)
             if bdata == 0:
                 self.retry += 1
                 self.doPost(api,data)
             else:
                self.retry = 0 
                return bdata
          else:
              print "Failed 5 retrys"
              sys.exit(1)

      def doTest(self,api,data={}):
         url = "https://%s:8080/API/1.1/%s" % (self.server,api)
         try:
             r = self.sess.post(url,data,verify=False,stream=True,allow_redirects=True)
             if r.status_code == requests.codes.ok:
                pass
             else:
                print "Proper code not returned %s doing retry" % r.status_code
                #self.logout()
                return 0
             ndata = ""
             for data in r.iter_content(chunk_size=1024):
                 if data:
                    ndata += data
             if self.debugit == "True":
                print ndata
                return ndata
             else:
                return ndata
         except requests.exceptions.Timeout:
             print "Request Timeout during doPost function doing retry"
             return 0

      def getDevices(self,data={}):
         url = "search/resource" 
         ndata = self.doPost(url,data)
         return ndata

      def getShardStats(self):
          url = "shards/stats"
          data = json.loads(self.doGet(url))
          return self.checkData(data)

      def getAudit(self,data={}):
          api = "search/audit"
          ndata = self.doPost(api,data)
          return ndata

      def getShardLists(self):
          url = "shards/list"
          data = json.loads(self.doGet(url))
          return self.checkData(data)         

      def getGroups(self):
          url = "group"
          data = json.loads(self.doGet(url))
          return self.checkData(data)

      def getEvents(self,data):
         api = "search/events"
         ndata = self.doPost(api,data)
         return ndata

      def getIncidents(self,data={}):
          api = "search/incidents"
          ndata = self.doPost(api,data)
          return ndata

      def getVulns(self,data={}):
          api = "search/vulnerabilities"
          ndata = self.doPost(api,data)
          return ndata

      def getUsers(self,data={}):
          api = "search/users"
          ndata = self.doPost(api,data)
          return ndata

      def getHelper(self,data):
          ndata = json.loads(data)
          return self.checkData(ndata)

      def sendmail(name,subj,text):
          sg = MIMEMultipart()
          msg['Subject'] = subj
          msg['From'] = "soc@acs-inc.com"
          msg['To'] = name
          p = MIMText(text,'plain')
          Encoders.encode_base64(part)
          msg.attach(p)
          server = smtplib.SMTP("127.0.0.1")
          #server = smtplib.SMTP('198.148.129.118')
          server.sendmail("hawkAPI",name,msg.as_string())
      #---------------------------------------------
      # API Functions
      #---------------------------------------------

      def getAllUsers(self):
              bdata = {"column[]":"uid"}
              return self.getHelper(self.getUsers(ndata))

      def getUsersByGroup(self,client):
          ndata = {"column[0]":"uid",
                   "column[1]":"username",
                   "column[2]":"email",
                   "column[3]":"fullname",
                   "column[4]":"timezone",
                   "column[5]":"email_recipient",
                   "column[6]":"account_lock",
                   "column[7]":"group_name",
                   "column[8]":"phone",
                   "column[9]":"phone2",
                   "column[10]":"signature",
                   "column[11]":"audit",
                   "column[12]":"log",
                   "column[13]":"search",
                   "column[14]":"event_manager",
                   "column[15]":"sysop",
                   "column[16]":"reports",
                   "column[17]":"filter_manager",
                   "column[18]":"moderator",
                   "column[19]":"admin",
                   "where[0]":"group_name = '%s'" % client}
          return self.getHelper(self.getUsers(ndata))


      def getResByGroup(self,client,mtype=""):
          '''
          Fixed Duplicate Resources
          Added a dic to return resource and total
          resource = json
          total = total count of resources          
          --------------------------------------------------
          class_type,resource_name,os_type_details
          resource_group,resource_id,class_name,class_detail
          resource_address6,recource_detail,resource_address
          date_added,last_seen,os_type_name
          --------------------------------------------------
           Special note:  the return at times will not produce
                          all these columns
          '''
          ndata = {"column[0]":"resource_name",
                   "where[0]":"resource_group = '%s'" % client}
          if mtype != "":
              ndata.update({"where[1]":"class_type != '%s'" % mtype})

          data = self.getHelper(self.getDevices(ndata))
          resource = []
          final = {"total":0,"resource":[]}
          for i in data:
               if  i["resource_name"] in resource:
                   pass
               else:
                   resource.append(i["resource_name"])
                   final["resource"].append(i)
                   final["total"] += 1
          return final

      def getResTypeByGroup(self,client,mtype="IDS"):
          ndata = {"column[0]":"resource_name",
                  "where[0]":"resource_group = '%s'" % client,
                  "where[1]":"class_type = '%s'" % mtype}
          data = self.getHelper(self.getDevices(ndata))
          resource = []
          final = {"total":0,"resource":[]}
          for i in data:
               if  i["resource_name"] in resource:
                   pass
               else:
                   resource.append(i["resource_name"])
                   final["resource"].append(i)
                   final["total"] += 1
          return final

      def getResType(self,mtype="IDS"):
          ndata = {"column[0]":"resource_name",
                   "column[1]":"class_type",
                   "where[1]":"class_type = '%s'" % mtype}
          data = self.getHelper(self.getDevices(ndata))
          resource = []
          final = {"total":0,"resource":[]}
          for i in data:
               if  i["resource_name"] in resource:
                   pass
               else:
                   resource.append(i["resource_name"])
                   final["resource"].append(i)
                   final["total"] += 1
          return final

      def getTopGroups(self,start,end,lm=0):
          ndata = {"column[0]":"group_name",
                   "column[1]":"count group_name",
                   "group_by":"group_name",
                   "order_by":"group_name_count DESC",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          return self.getHelper(self.getEvents(ndata))

      def getTopAlerts(self,start,end,lm=0):
          ndata = {"column[0]":"alert_name",
                   "column[1]":"count alert_name",
                   "column[2]":"group_name",
                   "group_by":"alert_name,group_name",
                   "order_by":"alert_name_count DESC",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          return self.getHelper(self.getEvents(ndata))

      def getTopAlertsByGroup(self,start,end,client,lm=0):
          ndata = {"column[0]":"alert_name",
                   "column[1]":"count alert_name",
                   "group_by":"alert_name",
                   "order_by":"alert_name_count DESC",
                   "where[0]":"group_name = '%s'" % client,
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          return self.getHelper(self.getEvents(ndata))



      def getAllPriority(self,start,end):
          ndata = {"column[0]":"priority",
                   "column[1]":"count priority",
                   "column[2]":"group_name",
                   "group_by":"priority,group_name",
                   "order_by":"priority_count DESC",
                   "begin":"%s" % start,
                   "end":"%s" % end,
                   "limit":"5"}
          return self.getHelper(self.getEvents(ndata))

      def getAllPriorityByGroup(self,start,end,group,lm=0):
         ndata = {"column[0]":"priority",
                  "column[1]":"count priority",
                  "group_by":"priority",
                  "order_by":"priority_count DESC",
                  "where[0]":"group_name = '%s'" % group,
                  "begin":"%s" % start,
                  "end":"%s" % end}
         if lm != 0:
              ndata.update({"limit":"%s" % lm})
         return self.getHelper(self.getEvents(ndata))
         
      def getAllIdsPriorityByGroup(self,start,end,group,lm=0):
         ndata = {"column[0]":"priority",
                  "column[1]":"count priority",
                  "group_by":"priority",
                  "order_by":"priority_count DESC",
                  "where[0]":"group_name = '%s'" % group,
                  "where[1]":"class_type = 'IDS'",
                  "begin":"%s" % start,
                  "end":"%s" % end}
         if lm != 0:
              ndata.update({"limit":"%s" % lm})
         return self.getHelper(self.getEvents(ndata))



      def getTopIpSrc(self,start,end,lm=0):
             ndata = {"column[0]":"ip_src",
                      "column[1]":"count ip_src",
                      "column[2]":"group_name",
                      "group_by":"ip_src,group_name",
                      "order_by":"ip_src_count DESC",
                      "where[0]":"ip_src != '138.69.211.22'",
                      "begin":"%s" % start,
                      "end":"%s" % end}
             if lm != 0:
                ndata.update({"limit":"%s" % lm})
             return self.getHelper(self.getEvents(ndata))

      def getTopIpSrcByGroup(self,start,end,client,lm=0):
             ndata = {"column[0]":"ip_src",
                      "column[1]":"count ip_src",
                      "group_by":"ip_src",
                      "order_by":"ip_src_count DESC",
                      "where[0]":"group_name = '%s'" % client,
                      "where[1]":"ip_src != '138.69.211.22'",
                      "begin":"%s" % start,
                      "end":"%s" % end}
             if lm != 0:
                ndata.update({"limit":"%s" % lm})
             return self.getHelper(self.getEvents(ndata))

      def getTopIdsIpSrcByGroup(self,start,end,client,lm=0):
             ndata = {"column[0]":"ip_src",
                      "column[1]":"count ip_src",
                      "group_by":"ip_src",
                      "order_by":"ip_src_count DESC",
                      "where[0]":"group_name = '%s'" % client,
                      "where[1]":"ip_src != '138.69.211.22'",
                      "where[2]":"class_type = 'IDS'",
                      "begin":"%s" % start,
                      "end":"%s" % end}
             if lm != 0:
                ndata.update({"limit":"%s" % lm})
             return self.getHelper(self.getEvents(ndata))

      def getTopIpDst(self,start,end,lm=0):
             ndata = {"column[0]":"ip_dst",
                      "column[1]":"count ip_dst",
                      "column[2]":"group_name",
                      "group_by":"ip_dst,group_name",
                      "order_by":"ip_dst_count DESC",
                      "where[0]":"ip_dst != '138.69.211.22'",
                      "begin":"%s" % start,
                      "end":"%s" % end}
             if lm != 0:
                ndata.update({"limit":"%s" % lm})
             return self.getHelper(self.getEvents(ndata))

      def getTopIpDstByGroup(self,start,end,client,lm=0):
             ndata = {"column[0]":"ip_dst",
                      "column[1]":"count ip_dst",
                      "group_by":"ip_dst",
                      "order_by":"ip_dst_count DESC",
                      "where[0]":"group_name = '%s'" % client,
                      "where[1]":"ip_dst != '138.69.211.22'",
                      "begin":"%s" % start,
                      "end":"%s" % end}
             if lm != 0:
                ndata.update({"limit":"%s" % lm})
             return self.getHelper(self.getEvents(ndata))

      def getTopIdsIpDstByGroup(self,start,end,client,lm=0):
             ndata = {"column[0]":"ip_dst",
                      "column[1]":"count ip_dst",
                      "group_by":"ip_dst",
                      "order_by":"ip_dst_count DESC",
                      "where[0]":"group_name = '%s'" % client,
                      "where[1]":"ip_dst != '138.69.211.22'",
                      "where[2]":"class_type = 'IDS'",
                      "begin":"%s" % start,
                      "end":"%s" % end}
             if lm != 0:
                ndata.update({"limit":"%s" % lm})
             return self.getHelper(self.getEvents(ndata))

      def getTopSrcCountry(self,start,end,lm=0):
          ndata = {"column[0]":"geoip_name ip_src",
                   "column[2]":"count ip_src_geoip_name",
                   "column[1]":"group_name",
                   "group_by":"ip_src_geoip_name,group_name",
                   "order_by":"ip_src_geoip_name_count DESC",
                   "where[0]":"ip_src_geoip_name != ''", 
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          return self.getHelper(self.getEvents(ndata))

      def getTopSrcCountryByGroup(self,start,end,client,lm=0):
          ndata = {"column[0]":"geoip_name ip_src",
                   "column[2]":"count ip_src_geoip_name",
                   "group_by":"ip_src_geoip_name",
                   "order_by":"ip_src_geoip_name_count DESC", 
                   "where[0]":"group_name = '%s'" % client,
                   "where[1]":"ip_src_geiop_name != ''",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          return self.getHelper(self.getEvents(ndata))

      def getTopDstCountry(self,start,end,lm=0):
          ndata = {"column[0]":"geoip_name ip_dst",
                   "column[2]":"count ip_dst_geoip_name",
                   "column[1]":"group_name",
                   "group_by":"ip_dst_geoip_name,group_name",
                   "order_by":"ip_dst_geoip_name_count DESC",
                   "where[0]":"ip_dst_geoip_name != ''", 
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          return self.getHelper(self.getEvents(ndata))

      def getTopDstCountryByGroup(self,start,end,client,lm=0):
          ndata = {"column[0]":"geoip_name ip_dst",
                   "column[2]":"count ip_dst_geoip_name",
                   "group_by":"ip_dst_geoip_name",
                   "order_by":"ip_dst_geoip_name_count DESC", 
                   "where[0]":"group_name = '%s'" % client,
                   "where[1]":"ip_dst_geoip_name != ''",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          return self.getHelper(self.getEvents(ndata))

      def getAllRes(self):
          ndata = {"column[]":"resource_name"}
          return self.getHelper(self.getDevices(ndata))

      def getTopRes(self,start,end,lm=0):
          ndata = {"column[0]":"resource_name",
                   "column[1]":"count resource_name",
                   "column[2]":"group_name",
                   "group_by":"resource_name,group_name",
                   "order_by":"resource_name_count DESC",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          return self.getHelper(self.getEvents(ndata))

      def getTopResByGroup(self,start,end,client,lm=0):
          ndata = {"column[0]":"resource_name",
                   "column[1]":"count resource_name",
                   "group_by":"resource_name",
                   "order_by":"resource_name_count DESC",
                   "where[0]":"group_name = '%s'" % client,
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          return self.getHelper(self.getEvents(ndata))    
      
      def getIDSAlerts(self,start,end,lm=0,res=""):
          ndata = {"column[1]":"date_added",
                   "column[2]":"ip_src",
                   "column[3]":"ip_dst",
                   "column[4]":"alert_name",
                   "column[5]":"group_name",
                   "column[6]":"geoip_name ip_src",
                   "column[7]":"geoip_name ip_dst",
                   "order_by":"date_added",
                   "where[0]":"class_type = 'IDS'",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          if res != "":
              ndata.update({"where[1]":"resource_name = '%s'" % res})
          return self.getHelper(self.getEvents(ndata))

      def getIDSAlertsByGroup(self,start,end,group,lm=0,res=""):
          ndata = {"column[1]":"date_added",
                   "column[2]":"ip_src",
                   "column[3]":"ip_dst",
                   "column[4]":"alert_name",
                   "column[5]":"group_name",
                   "column[6]":"geoip_name ip_src",
                   "column[7]":"geoip_name ip_dst",
                   #"order_by":"date_added",
                   "where[0]":"class_type = 'IDS'",
                   "where[1]":"group_name = '%s'" % group,
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          if res != "":
              ndata.update({"where[2]":"resource_name = '%s'" % res})
          return self.getHelper(self.getEvents(ndata))

      def getTopIdsAlertsByGroup(self,start,end,group,lm=0):
          ndata = {"column[1]":"alert_name",
                   "column[2]":"count alert_name",
                   "column[3]":"group_name",
                   "column[4]":"class_type",
                   "group_by":"alert_name",
                   "order_by":"alert_name_count DESC",
                   "where[0]":"class_type = 'IDS'",
                   "where[1]":"group_name = '%s'" % group,
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          return self.getHelper(self.getEvents(ndata))

      def getAlerts(self,start,end,lm=0,ct=""):
          ndata = {"column[1]":"date_added",
                   "column[2]":"ip_src",
                   "column[3]":"ip_dst",
                   "column[4]":"alert_name",
                   "column[5]":"group_name",
                   "column[6]":"geoip_name ip_src",
                   "column[7]":"geoip_name ip_dst",
                   "order_by":"date_added",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          if ct != "":
             ndata.update({"where[0]":"class_type = '%s'" % ct}) 
          return self.getHelper(self.getEvents(ndata))

      def getAlertsByGroup(self,start,end,group,lm=0,ct="",an=""):
          ndata = {"column[1]":"date_added",
                   "column[2]":"ip_src",
                   "column[3]":"ip_dst",
                   "column[4]":"alert_name",
                   "column[5]":"group_name",
                   "column[6]":"geoip_name ip_src",
                   "column[7]":"geoip_name ip_dst",
                   "order_by":"date_added",
                   "where[0]":"group_name = '%s'" % group,
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
              ndata.update({"limit":"%s" % lm})
          if ct != "":
             ndata.update({"where[1]":"class_type = '%s'" % ct})
          if an != "":
              ndata.update({"where[2]":"alert_name = '%s'" % an})
          return self.getHelper(self.getEvents(ndata))


      def getLowAlerts(self,start,end,lm=0,ct=""):
          ndata = {"column[0]":"date_added",
                   "column[1]":"ip_src",
                   "column[2]":"ip_dst",
                   "column[3]":"ip_dport",
                   "column[4]":"ip_sport",
                   "column[5]":"alert_name",
                   "column[6]":"name",
                   "column[7]":"alerts_type_name",
                   "order_by":"date_added",
                   "where[1]":"priority = (3 or 4 or 5)",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
             ndata.update({"limit":"%s" % lm})
          if ct != "":
             ndata.update({"where[0]":"class_type = '%s'" % ct})
          return self.getHelper(self.getEvents(ndata))

      def getLowAlertsByGroup(self,start,end,client,lm=0,ct=""):
          ndata = {"column[0]":"date_added",
                   "column[1]":"ip_src",
                   "column[2]":"ip_dst",
                   "column[3]":"ip_dport",
                   "column[4]":"ip_sport",
                   "column[5]":"alert_name",
                   "column[6]":"name",
                   "column[7]":"alerts_type_name",
                   "order_by":"date_added",
                   "where[0]":"group_name = '%s'" % client,
                   "where[1]":"priority = (3 or 4 or 5)",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
             ndata.update({"limit":"%s" % lm})
          if ct != "":
             ndata.update({"where[2]":"class_type = '%s'" % ct})
          return self.getHelper(self.getEvents(ndata))

      def getMedAlerts(self,start,end,lm=0,ct=""):
          ndata = {"column[0]":"date_added",
                   "column[1]":"ip_src",
                   "column[2]":"ip_dst",
                   "column[3]":"ip_dport",
                   "column[4]":"ip_sport",
                   "column[5]":"alert_name",
                   "column[6]":"name",
                   "column[7]":"alerts_type_name",
                   "order_by":"date_added",
                   "where[1]":"priority = (2)",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
             ndata.update({"limit":"%s" % lm})
          if ct != "":
             ndata.update({"where[2]":"class_type = '%s'" % ct})
          return self.getHelper(self.getEvents(ndata))

      def getMedAlertsByGroup(self,start,end,client,lm=0,ct=""):
          ndata = {"column[0]":"date_added",
                   "column[1]":"ip_src",
                   "column[2]":"ip_dst",
                   "column[3]":"ip_dport",
                   "column[4]":"ip_sport",
                   "column[5]":"alert_name",
                   "column[6]":"name",
                   "column[7]":"alerts_type_name",
                   "order_by":"date_added",
                   "where[0]":"group_name = '%s'" % client,
                   "where[1]":"priority = (2)",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
             ndata.update({"limit":"%s" % lm})
          if ct != "":
             ndata.update({"where[2]":"class_type = '%s'" % ct})
          return self.getHelper(self.getEvents(ndata))

      def getHighAlerts(self,start,end,lm=0,ct=""):
          ndata = {"column[0]":"date_added",
                   "column[1]":"ip_src",
                   "column[2]":"ip_dst",
                   "column[3]":"ip_dport",
                   "column[4]":"ip_sport",
                   "column[5]":"alert_name",
                   "column[6]":"resource_name",
                   "column[7]":"alerts_type_name",
                   "order_by":"date_added",
                   "where[1]":"priority = (1)",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
             ndata.update({"limit":"%s" % lm})
          if ct != "":
             ndata.update({"where[2]":"class_type = '%s'" % ct})
          return self.getHelper(self.getEvents(ndata))

      def getHighAlertsByGroup(self,start,end,client,lm=0,ct=""):
          ndata = {"column[0]":"date_added",
                   "column[1]":"ip_src",
                   "column[2]":"ip_dst",
                   "column[3]":"ip_dport",
                   "column[4]":"ip_sport",
                   "column[5]":"alert_name",
                   "column[6]":"resource_name",
                   "column[7]":"alerts_type_name",
                   "order_by":"date_added",
                   "where[0]":"group_name = '%s'" % client,
                   "where[1]":"priority = (1)",
                   "begin":"%s" % start,
                   "end":"%s" % end}
          if lm != 0:
             ndata.update({"limit":"%s" % lm})
          if ct != "":
             ndata.update({"where[2]":"class_type = '%s'" % ct})
          return self.getHelper(self.getEvents(ndata))


      def searchIpSrc(self,start,end,ip,lm=0):
           ndata = {"column[0]":"ip_src",
                    "column[1]":"ip_dst",
                    "column[2]":"alert_name",
                    "column[3]":"date_added",
                    "column[4]":"alerts_type_name",
                    "column[5]":"name",
                    "column[6]":"ip_dport",
                    "column[7]":"ip_sport",
                    "column[8]":"priority",
                    "column[9]":"group_name",
                    "where[0]":"ip_src = ('%s')" % ip,
                    "begin":"%s" % start,
                    "end":"%s" % end}
           if lm != 0:
              ndata.update({"limit":"%s" % lm})
           return self.getHelper(self.getEvents(ndata))

      def searchIpSrcByGroup(self,start,end,ip,client,lm=0):
           ndata = {"column[0]":"ip_src",
                    "column[1]":"ip_dst",
                    "column[2]":"alert_name",
                    "column[3]":"date_added",
                    "column[4]":"alerts_type_name",
                    "column[5]":"name",
                    "column[6]":"ip_dport",
                    "column[7]":"ip_sport",
                    "column[8]":"priority",
                    "column[9]":"group_name",
                    "where[0]":"group_name = '%s'" % client,
                    "where[1]":"ip_src = ('%s')" % ip,
                    "begin":"%s" % start,
                    "end":"%s" % end}
           if lm != 0:
              ndata.update({"limit":"%s" % lm})
           return self.getHelper(self.getEvents(ndata))
 
      def searchIpDst(self,start,end,ip,lm=0):
           ndata = {"column[0]":"ip_src",
                    "column[1]":"ip_dst",
                    "column[2]":"alert_name",
                    "column[3]":"date_added",
                    "column[4]":"alerts_type_name",
                    "column[5]":"name",
                    "column[6]":"ip_dport",
                    "column[7]":"ip_sport",
                    "column[8]":"priority",
                    "column[9]":"group_name",
                    "where[0]":"ip_dst = ('%s')" % ip,
                    "begin":"%s" % start,
                    "end":"%s" % end}
           if lm != 0:
              ndata.update({"limit":"%s" % lm})
           return self.getHelper(self.getEvents(ndata))

      def searchIpDstByGroup(self,start,end,ip,client,lm=0):
           ndata = {"column[0]":"ip_src",
                    "column[1]":"ip_dst",
                    "column[2]":"alert_name",
                    "column[3]":"date_added",
                    "column[4]":"alerts_type_name",
                    "column[5]":"name",
                    "column[6]":"ip_dport",
                    "column[7]":"ip_sport",
                    "column[8]":"priority",
                    "column[9]":"group_name",
                    "where[0]":"group_name = '%s'" % client,
                    "where[1]":"ip_dst = ('%s')" % ip,
                    "begin":"%s" % start,
                    "end":"%s" % end}
           if lm != 0:
              ndata.update({"limit":"%s" % lm})
           return self.getHelper(self.getEvents(ndata))

      def searchRes(self,start,end,res,lm=0):
           ndata = {"column[0]":"ip_src",
                    "column[1]":"ip_dst",
                    "column[2]":"alert_name",
                    "column[3]":"date_added",
                    "column[4]":"alerts_type_name",
                    "column[5]":"name",
                    "column[6]":"ip_dport",
                    "column[7]":"ip_sport",
                    "column[8]":"priority",
                    "column[9]":"group_name",
                    "column[10]":"resource_name",
                    "where[0]":"resource_name = ('%s')" % res,
                    "order_by":"date_added ASC",
                    "begin":"%s" % start,
                    "end":"%s" % end}
           if lm != 0:
              ndata.update({"limit":"%s" % lm})
           return self.getHelper(self.getEvents(ndata))

      def searchResByGroup(self,start,end,res,group,lm=0):
           ndata = {"column[0]":"ip_src",
                    "column[1]":"ip_dst",
                    "column[2]":"alert_name",
                    "column[3]":"date_added",
                    "column[4]":"alerts_type_name",
                    "column[5]":"name",
                    "column[6]":"ip_dport",
                    "column[7]":"ip_sport",
                    "column[8]":"priority",
                    "column[9]":"group_name",
                    "column[10]":"resource_name",
                    "where[0]":"resource_name = ('%s')" % res,
                    "where[1]":"group_name = ('%s')" % group,
                    "begin":"%s" % start,
                    "end":"%s" % end}
           if lm != 0:
              ndata.update({"limit":"%s" % lm})
           return self.getHelper(self.getEvents(ndata))

      def getSuccessLoginsByGroup(self,start,end,client,ip="",lm=0,tp="action"):
           ndata = {"column[0]":"correlation_username",
                    "column[0]":"date_added",
                    "column[1]":"ip_src",
                    "column[2]":"alert_name",
                    "column[3]":"name",
                    "column[5]":"group_name",
                    "where[0]":"group_name = '%s'" % client, 
                    "where[1]":"correlation_username != ''",
                    "begin":"%s" % start,
                    "end":"%s" % end}
           if lm != 0:
              ndata.update({"limit":"%s" % lm})
           if ip != "":
              ndata.update({"where[3]":"ip_src = '%s'" % ip})
           if tp == "login":
              ndata.update({"where[2]":"audit_login = ('success')"})
           elif tp == "action":
               ndata.update({"where[2]":"audit_user_action = ('success')"}) 
           return self.getHelper(self.getEvents(ndata))

      def getFailedLoginsByGroup(self,start,end,client,ip="",lm=0,tp="login"):
           ndata = {"column[0]":"correlation_username",
                    "column[0]":"date_added",
                    "column[1]":"ip_src",
                    "column[2]":"alert_name",
                    "column[3]":"name",
                    "column[5]":"group_name",
                    "where[0]":"group_name = '%s'" % client, 
                    "where[1]":"correlation_username != ''",
                    "begin":"%s" % start,
                    "end":"%s" % end}
           if lm != 0:
              ndata.update({"limit":"%s" % lm})
           if ip != "":
              ndata.update({"where[3]":"ip_src = '%s'" % ip})
           if tp == "login":
              ndata.update({"where[2]":"audit_login = ('failure')"})
           elif tp == "action":
              ndata.update({"where[2]":"audit_user_action = ('failure')"})
           return self.getHelper(self.getEvents(ndata))

      def getTopVulns(self,client,lm=10):
          ndata = {"column[0]":"vuln_name",
                   "column[1]":"count vuln_name",
                   "column[2]":"group_name",
                   "group_by":"vuln_name",
                   "order_by":"vuln_name_count DESC",
                   "where[0]":"group_name = ('%s')" % client,
                   "limit":"%s" % str(lm)}
          return self.getHelper(self.getVulns(ndata))

      def getTopVulnSev(self,client,lm=10):
          ndata = {"column[0]":"severity",
                  "column[1]":"count severity",
                  "column[2]":"group_name",
                  "group_by":"severity",
                  "order_by":"severity_count DESC",
                  "where[0]":"group_name = ('%s')" % client,
                  "limit":"%s" % str(lm)}
          return self.getHelper(self.getVulns(ndata))

      def getTopVulnHost(self,client,lm=10):
          ndata = {"column[0]":"resource_name",
                   "column[1]":"count resource_name",
                   "column[2]":"group_name",
                   "column[3]":"resource_address",
                   "group_by":"resource_name",
                   "order_by":"resource_name_count DESC",
                   "where[0]":"group_name = ('%s')" % client,
                   "limit":"%s" % str(lm)}
          return self.getHelper(self.getVulns(ndata))

      def getTopVulnPort(self,client,lm=10):
          ndata = {"column[0]":"ip_port",
                   "column[1]":"count ip_port",
                   "column[2]":"group_name",
                   "group_by":"ip_port",
                   "order_by":"ip_port_count DESC",
                   "where[0]":"group_name = ('%s')" % client,
                   "where[1]":"ip_port != '0'",
                   "limit":"%s" % str(lm)}
          return self.getHelper(self.getVulns(ndata))


      def deltaDates(self,d1,d2):
          st = datetime.strptime(d1,"%m/%d/%Y %H:%M:%S")
          et = datetime.strptime(d2,"%m/%d/%Y %H:%M:%S")
          mins = (et-st).total_seconds()/60
          return mins

      def buildDates(self,d1,d2,type=0):
          dates = []
          st = datetime.strptime(d1,"%m/%d/%Y %H:%M:%S")
          et = datetime.strptime(d2,"%m/%d/%Y %H:%M:%S")
          mins = (et-st).total_seconds()/60
          totals = int(mins)/5
          idit = 1
          for i in range(1,totals+10):
              if i == 1:
                 end = st + timedelta(minutes=5)
                 fend = datetime.strftime(end,"%m/%d/%Y %H:%M:%S")
                 dates.append([datetime.strftime(st,"%m/%d/%Y %H:%M:%S"),
                              fend,idit])
                 idit += 1
                 nstart = end
              else:
                 start = nstart
                 end = nstart + timedelta(minutes=5)
                 if end > et:
                    dates.append([datetime.strftime(start,"%m/%d/%Y %H:%M:%S"),
                                  datetime.strftime(et,"%m/%d/%Y %H:%M:%S"),
                                  idit])
                    break
                 else:
                    dates.append([datetime.strftime(start,"%m/%d/%Y %H:%M:%S"),
                                  datetime.strftime(end,"%m/%d/%Y %H:%M:%S"),
                                  idit])

                 idit += 1
                 nstart = end
          return dates

      def getDateLocal(self,dtype="d",delta=0):
           if delta < 1:
              t = datetime.utcnow()
              return t.replace(microsecond=0)
           else:
              data = int(delta)
              dtype = dtype.lower()
              if dtype == "d":
                 t = datetime.now() - timedelta(days = data)
                 return t.replace(microsecond=0)
              elif dtype == "h":
                 t = datetime.now() - timedelta(hours = data)
                 return t.replace(microsecond=0)
              elif dtype == "m":
                 t = datetime.now() - timedelta(minutes = data)
                 return t.replace(microsecond=0)
              elif dtype == "s":
                 t = datetime.now() - timedelta(seconds = data)
                 return t.replace(microsecond=0)
              else:
                self.callError('Wrong value for dtype in getDateLocal expected m or d or h or s',str(dtype))
                sys.exit(1)
      
      def getDateUtc(self,dtype="d",delta=0):
           if delta < 1:
              t = datetime.utcnow()
              return t.replace(microsecond=0)
           else:
              data = int(delta)
              dtype = dtype.lower()
              if dtype == "d":
                 t = datetime.utcnow() - timedelta(days = data)
                 return t.replace(microsecond=0)
              elif dtype == "h":
                 t = datetime.utcnow() - timedelta(hours = data)
                 return t.replace(microsecond=0)
              elif dtype == "m":
                 t = datetime.utcnow() - timedelta(minutes = data)
                 return t.replace(microsecond=0)
              elif dtype == "s":
                 t = datetime.utcnow() - timedelta(seconds = data)
                 return t.replace(microsecond=0)
              else:
                self.callError('Wrong value for dtype in getDateUtc expected m or d or h or s',str(dtype))
                sys.exit(1)  
    
      def print_table(self,rows):
          widths = [ len(max(columns, key=len)) for columns in zip(*rows) ]
          header, data = rows[0], rows[1:]
          print(
                ' | '.join( format(title, "%ds" % width) for width, title in zip(widths, header) )
          )
          print( '-+-'.join( '-' * width for width in widths ) )
          for row in data:
             print(
                   " | ".join( format(cdata, "%ds" % width) for width, cdata in zip(widths, row) )
             )

      def create_csv(self,keys,data):
          f = ""
          ndata = []
          for i in keys:
              f += "%s," % i
              ndata.append(i)
          f = f[:-1]
          f += "\n"
          for i in data:
              for b in ndata:
                  if b not in i:
                     f += "NONE,"
                  else: 
                     f += "%s," % i[b]
              f = f[:-1]
              f += "\n"
          return f
       
      def getKeys(self,data):
          all = []
          for i in data:
              for f in i.keys():
                  if f in all:
                     pass
                  else:
                     all.append(f)
          return all

      def traverse(self,data):
           res = []
           for b in o:
               if b["children"] == False:
                  res.append(b["key"])          
               else:
                  res.append(b["key"])
                  res.extend(traverse(b["children"]))
           return res
          
