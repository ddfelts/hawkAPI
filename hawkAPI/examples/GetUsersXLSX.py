#!/usr/bin/python
import time
import sys
import string
from hawkAPI import hawkAPI2
from hawkAPI import hawkPdf
from datetime import datetime, date, time
from optparse import OptionParser
import xlsxwriter

usage = 'GetUsersXLSX -u "id" -p "pass" -i "server" -c "client" -l directory'

parser = OptionParser(usage=usage)
parser.add_option("-u",dest="user",help="Username")
parser.add_option("-p",dest="passw",help="Password")
parser.add_option("-i",dest="server",help="The hawk server IP")
parser.add_option("-c",dest="client",help="Client name")
parser.add_option("-l",dest="dir",help="location to store")

(opt,args) = parser.parse_args()
if not opt.user:
   parser.error("No User id provided")
if not opt.passw:
   parser.error("No Password provided")
if not opt.server:
   parser.error("Hawk IP address")
if not opt.client:
   parser.error("No Client Set")
if not opt.dir:
   parser.error("Directory to save files")

hawk = hawkAPI2.hawkAPI(opt.server)
hawk.login(opt.user,opt.passw)

def doGet(client):
   data = hawk.getUsersByGroup(client)
   return data
   
def spreadSheet(filename, keys, mydata):
	wkbook = xlsxwriter.Workbook(filename)
	ws = wkbook.add_worksheet()
	textwrap = wkbook.add_format({'text_wrap': True, 'align':'center','border':0})
	align = wkbook.add_format({'text_wrap': True, 'align':'left','border':0})
	bold = wkbook.add_format({'bold': True, 'bg_color':'yellow', 'border':1, 'align':'center'})
	ws.set_column(0, 18, 10) 
	ws.set_column(0, 0, 15) 
	ws.set_column(2, 2, 6) 
	ws.set_column(4, 4, 5) 
	ws.set_column(5, 6, 13)   
	ws.set_column(8, 8, 15)   
	ws.set_column(9, 10, 12)   
	ws.set_column(11, 11, 15)   
	ws.set_column(13, 13, 15)
	ws.set_column(15, 15, 25)   
	ws.set_column(16, 16, 20)   
	ws.set_column(17, 17, 35)      
	
	col=0
	for x in keys:
		if x != 'signature':
			ws.write(0, col, x.capitalize(), bold)
			col+=1
				
	row = 1
	col = 0
	for x in mydata:
		ws.write(row, col, x["username"], align) 
		ws.write(row, col+1, x["audit"], textwrap) 
		ws.write(row, col+2, x["search"], textwrap) 
		ws.write(row, col+3, x["admin"], textwrap) 
		ws.write(row, col+4, x["uid"], textwrap) 
		ws.write(row, col+5, x["phone"], textwrap) 
		ws.write(row, col+6, x["phone2"], textwrap) 
		ws.write(row, col+7, x["reports"], textwrap) 
		ws.write(row, col+8, x["group_name"], textwrap) 
		ws.write(row, col+9, x["moderator"], textwrap) 
		ws.write(row, col+10, x["account_lock"], textwrap) 
		ws.write(row, col+11, x["filter_manager"], textwrap) 
		ws.write(row, col+12, x["sysop"], textwrap) 
		ws.write(row, col+13, x["email_recipient"], textwrap) 
		ws.write(row, col+14, x["timezone"], textwrap) 
		ws.write(row, col+15, x["fullname"], textwrap) 
		ws.write(row, col+16, x["event_manager"], textwrap) 
		ws.write(row, col+17, x["email"], textwrap) 
		ws.write(row, col+18, x["log"], textwrap) 
		row += 1
	wkbook.close()
	   
if __name__ == '__main__':
	
	mydata = doGet(opt.client)
	keys = hawk.getKeys(mydata)
	
	nameit = opt.dir + opt.client + ".xlsx"
	spreadSheet(nameit, keys, mydata)
	
	hawk.logout()
	sys.exit(1)