# Burp extension to modify OPTIONS requests - part two.

# modified "example traffic redirector" https://raw.githubusercontent.com/PortSwigger/example-traffic-redirector/master/python/TrafficRedirector.py
# also https://www.optiv.com/blog/automatically-adding-new-header-with-burp

# support for burp-exceptions - see https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
    import sys
except ImportError:
    pass

from burp import IBurpExtender
from burp import ISessionHandlingAction 

class BurpExtender(IBurpExtender, ISessionHandlingAction):

    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # enable for burp-exceptions
        # sys.stdout = callbacks.getStdout()
        
        # set our extension name
        callbacks.setExtensionName("Filter OPTIONS 2")
        
        # register the extension to perform a session handling action
        # w/o this, the extension does not pop-up in the "perform action" part in session handling rules
        callbacks.registerSessionHandlingAction(self)

    #
    # implement ISessionHandlingAction
    #
    
    def getActionName(self):
        return "Add \"Accept: text/css,*/*\" header"
    
    def performAction(self, currentRequest, macroItems):
        # we modify currentRequest and then we are done.

        # get request bytes
        requestBytes = currentRequest.getRequest()
        # get request body
        requestInfo = self._helpers.analyzeRequest(requestBytes)
 
         # return if the verb is not OPTIONS
        if requestInfo.getMethod() != "OPTIONS":
            return

        # add "text/css" to the "Accept" header
        headers = requestInfo.getHeaders()
        headers.add("Accept: text/css,*/*")

        # re-create the message
        # to recreate it we need headers (we already have them) and then the body

        # get request bytes
        bodyBytes = requestBytes[requestInfo.getBodyOffset():]
        # if we wanted to modify the body, this would be the place

        # build a new message with
        modifiedMessage = self._helpers.buildHttpMessage(headers, bodyBytes)

        # set the request to the modifiedMessage
        currentRequest.setRequest(modifiedMessage)

        # and we are done
        return

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass