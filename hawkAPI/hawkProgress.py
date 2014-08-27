import os

class ProgressBar(object):
    def __init__(self,message,width=20,s=u"*",e=u" "):
        self.width = width
        if self.width < 0:
            self.width = 0
        self.message = message
        self.ps = s
        self.es = e


    def update(self,progress):
        totalBlocks = self.width
        filledBlocks = int(round(progress / (100 / float(totalBlocks)) ))
        emptyBlocks = totalBlocks - filledBlocks
        progressBar = self.ps * filledBlocks + \
        self.es * emptyBlocks
        if not self.message:
           self.message = u''
        progressMessage = u'\r{0} {1}  {2}%'.format(self.message,
                                                         progressBar,
                                                         progress)
        sys.stdout.write(progressMessage)
        sys.stdout.flush()

    def calculateAndUpdate(self, done, total):
        progress = int(round( (done / float(total)) * 100) )
        self.update(progress)
