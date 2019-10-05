# modified "example traffic redirector" 
# https://raw.githubusercontent.com/PortSwigger/example-traffic-redirector/master/python/TrafficRedirector.py
# Idea: https://github.com/pajswigger/filter-options/blob/master/src/filter-options.kt
# Usage: Put both files in a directory and add filter-options.py to Burp. Nees Jython.
# Blog post: https://parsiya.net/blog/2019-04-06-hiding-options-an-adventure-in-dealing-with-burp-proxy-in-an-extension/

# support for burp-exceptions - see https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
    import sys
except ImportError:
    pass

# support for burputils - https://github.com/parsiya/burputils
try:
    from burputils import BurpUtils
except ImportError:
    pass

from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    # implement IBurpExtender

    # set everything up
    def	registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self.utils = BurpUtils(callbacks.getHelpers())

        # support for burp-exceptions
        try:
            sys.stdout = callbacks.getStdout()
        except:
            pass
        
        # set our extension name
        callbacks.setExtensionName("Filter OPTIONS")
        
        # register an HTTP listener
        callbacks.registerHttpListener(self)

    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        # only process responses
        if messageIsRequest:
            return

        # now we only have responses

        # get the request associated with the response
        requestInfo = self.utils.getInfo(True, messageInfo)

        # return if the request method was not OPTIONS
        if requestInfo.getMethod() != "OPTIONS":
            return

        # get response info
        responseInfo = self.utils.getInfo(False, messageInfo)

        # get headers using utils
        headers = self.utils.getHeaders(responseInfo)

        # overwrite the Content-Type header. Overwrite adds the header if it
        # does not exist.
        headers.overwrite("Content-Type", "text/css; charset=UTF-8")

        # put everything back together
        bodyBytes = self.utils.getBody(messageIsRequest, messageInfo)

        # Debug
        # rawHeaders = headers.exportRaw()

        # build message
        modifiedmsg = self.utils.burpHelper.buildHttpMessage(headers.exportRaw(), bodyBytes)

        # set modified message response
        self.utils.setRequestResponse(messageIsRequest, modifiedmsg, messageInfo)

        # this should be reflected in response tab

        # done
        print "--------"
        return

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass