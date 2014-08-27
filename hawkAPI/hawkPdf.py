import time
import sys
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image, Table, TableStyle
from  reportlab.lib.styles import ParagraphStyle as PS
from  reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.rl_config import defaultPageSize
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Rect, Line
from reportlab.lib.colors import red, green, black, blue, lightblue

 

class ReportDocument(SimpleDocTemplate):

      def __init__(self,pdfName,**kw):
          apply(SimpleDocTemplate.__init__, (self, pdfName), kw)
          

      def afterFlowable(self, flowable):  
         "Registers TOC entries."  
         if flowable.__class__.__name__ == 'Paragraph':  
             text = flowable.getPlainText()
             style =  flowable.style.name
             if style == "Heading1": 
                self.notify('TOCEntry', (0, text, self.page))  
             
class HawkReport:

      def __init__(self,pdfName):
          self.doc = ReportDocument(pdfName)
          self.PAGE_HEIGHT=defaultPageSize[1]
          self.PAGE_WIDTH=defaultPageSize[0]
          self.story = []
          self.styles = getSampleStyleSheet()
          self.Title = ""
          self.startDate = ""
          self.endDate = ""
          self.client = ""
          self.image = ""

      def setTitle(self,title):
          self.Title = title

      def setClientName(self,name):
          self.client = name

      def setDate(self,start,end):
          self.startDate = start
          self.endDate = end

      def setClientImage(self,image):
          self.image = image

      def myFirstPage(self,canvas,doc):
          canvas.saveState()
          canvas.setFont("Times-Bold",30)
          canvas.drawString(1 * inch,9 * inch , self.Title)
          canvas.setFont("Times-Bold",16)
          canvas.drawString(1 * inch,8.5 * inch,"(%s) - (%s)" % (self.startDate,self.endDate))
          canvas.drawString(1 * inch,8.25 * inch,self.client)
          canvas.drawImage("/usr/local/lib/python2.7/dist-packages/hawkAPI/lib/waves.png",0,25,600,325)
          canvas.drawImage(self.image,self.PAGE_WIDTH/2.0,self.PAGE_HEIGHT-168)
          canvas.restoreState()

      def myLaterPage(self,canvas,doc):
          canvas.saveState()
          canvas.setFont("Times-Roman",10)
          canvas.drawString(6.25 * inch, self.PAGE_HEIGHT - 25,"Client Name: %s " % (self.client))
          canvas.line(.50 * inch, self.PAGE_HEIGHT - 50, 8 * inch, self.PAGE_HEIGHT - 50)
          canvas.line(.50 * inch,1 * inch, 8 * inch,1 * inch)
          canvas.drawString(inch, 0.75 * inch, "Page: %d" % (doc.page))
          canvas.restoreState()


      def createToc(self):
          centered = PS(name = 'centered',  
                        fontSize = 30,  
                        leading = 16,  
                        alignment = 1,  
                        spaceAfter = 20)
          self.story.append(Paragraph('<b>Table of contents</b>',centered))
          toc = TableOfContents()
          self.story.append(toc)
          self.addPageBreak()
          
      def addStory(self,text):
          t = Paragraph(text,self.styles["Normal"])
          self.story.append(t)
          self.story.append(Spacer(1,12))
      
      def addStoryTitle(self,text):
          t = Paragraph(text,self.styles["Heading1"])
          self.story.append(t)
          self.story.append(Spacer(1,12))
         
      def addTableIpSrc(self,ndata):
          data = [["Group","Ip Source","Count"]]
          for i in ndata:
               data.append([i["group_name"],i["ip_src"],i["ip_src_count"]])
          tblStyle = TableStyle([('TEXTCOLOR',(0,0),(-1,-1),black),
                       ('VALIGN',(0,0),(-1,-1),'TOP'),
                       ('BOX',(0,0),(-1,-1),1,black),
                       ('INNERGRID',(0,0),(-1,-1),1,black),
                       ('BACKGROUND',(0,0),(2,0),lightblue)])
          t = Table(data,colWidths="*")
          t.hAlign = 'LEFT'
          t.setStyle(tblStyle)
          self.story.append(t)


      def addTableIpSrcByGroup(self,ndata):
          data = [["Ip Source","Count"]]
          for i in ndata:
               data.append([i["ip_src_text"],i["ip_src_count"]])
          tblStyle = TableStyle([('TEXTCOLOR',(0,0),(-1,-1),black),
                       ('VALIGN',(0,0),(-1,-1),'TOP'),
                       ('LINEBELOW',(0,0),(-1,-1),1,black),
                       ('BOX',(0,0),(-1,-1),1,black),
                       ('BOX',(0,0),(0,-1),1,black),
                       ('BACKGROUND',(0,0),(1,0),lightblue)])
          t = Table(data,colWidths="*")
          t.hAlign = 'LEFT'
          t.setStyle(tblStyle)
          self.story.append(t)

      def addTableIpDst(self,ndata):
          data = [["Group","Ip Dst","Count"]]
          for i in ndata:
               data.append([i["group_name"],i["ip_dst"],i["ip_dst_count"]])
          tblStyle = TableStyle([('TEXTCOLOR',(0,0),(-1,-1),black),
                       ('VALIGN',(0,0),(-1,-1),'TOP'),
                       ('BOX',(0,0),(-1,-1),1,black),
                       ('INNERGRID',(0,0),(-1,-1),1,black),
                       ('BACKGROUND',(0,0),(2,0),lightblue)])
          t = Table(data,colWidths="*")
          t.hAlign = 'LEFT'
          t.setStyle(tblStyle)
          self.story.append(t)

      def addTableIpDstByGroup(self,ndata):
          data = [["IP Dst","Count"]]
          for i in ndata:
                data.append([i["ip_dst"],i["ip_dst_count"]])
          tblStyle = TableStyle([('TEXTCOLOR',(0,0),(-1,-1),black),
                       ('VALIGN',(0,0),(-1,-1),'TOP'),
                       ('LINEBELOW',(0,0),(-1,-1),1,black),
                       ('BOX',(0,0),(-1,-1),1,black),
                       ('BOX',(0,0),(0,-1),1,black),
                       ('BACKGROUND',(0,0),(1,0),lightblue)])
          t = Table(data,colWidths="*")
          t.hAlign = 'LEFT'
          t.setStyle(tblStyle)
          self.story.append(t)


      def addTableDefault(self,ndata):
          tblStyle = TableStyle([('TEXTCOLOR',(0,0),(-1,-1),black),
                                 ('VALIGN',(0,0),(-1,-1),'TOP'),
                                 ('LINEBELOW',(0,0),(-1,-1),1,black),
                                 ('BOX',(0,0),(-1,-1),1,black),
                                 ('BOX',(0,0),(0,-1),1,black),
                                 ('BACKGROUND',(0,0),(1,0),lightblue)])
          t = Table(ndata,colWidths="*")
          t.setStyle(tblStyle)
          self.story.append(t)

      def addTable(self,ndata):
          tblStyle = TableStyle([('TEXTCOLOR',(0,0),(-1,-1),black),
                                 ('VALIGN',(0,0),(-1,-1),'TOP'),
                                 ('BOX',(0,0),(-1,-1),1,black),
                                 ('INNERGRID',(0,0),(-1,-1),1,black),
                                 ('BACKGROUND',(0,0),(2,0),lightblue)])
          
          t = Table(ndata,colWidths="*")
          t.setStyle(tblStyle)
          self.story.append(t)
 
      def addTableAlerts(self,ndata):
          data = [["Alert Name","Count"]]
          for i in ndata:
              data.append([i["alert_name"],i["alert_name_count"]])
          tblStyle = TableStyle([('TEXTCOLOR',(0,0),(-1,-1),black),
                       ('VALIGN',(0,0),(-1,-1),'TOP'),
                       ('LINEBELOW',(0,0),(-1,-1),1,black),
                       ('BOX',(0,0),(-1,-1),1,black),
                       ('BOX',(0,0),(0,-1),1,black),
                       ('BACKGROUND',(0,0),(1,0),lightblue)])
          t = Table(data)
          t.setStyle(tblStyle)
          self.story.append(t) 

      def addDefaultTable(self,data):
          tblStyle = TableStyle([('TEXTCOLOR',(0,0),(-1,-1),black),
                       ('VALIGN',(0,0),(-1,-1),'TOP'),
                       ('INNERGRID',(0,0),(-1,-1),1,black),
                       ('BOX',(0,0),(-1,-1),1,black),
                       ('BACKGROUND',(0,0),(-1,0),lightblue)])
          t = Table(data,colWidths="*")
          t.hAlign = 'LEFT'
          t.setStyle(tblStyle)
          self.story.append(t)

      def addImage(self,image):
          self.story.append(Image(image,500,250))
          self.story.append(Spacer(1,12))

      def addPageBreak(self):
          self.story.append(PageBreak())

      def savePdf(self):
          self.doc.multiBuild(self.story,onFirstPage=self.myFirstPage, onLaterPages=self.myLaterPage)
