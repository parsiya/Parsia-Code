# Burp extension to modify OPTIONS requests.
# modified "example traffic redirector" https://raw.githubusercontent.com/PortSwigger/example-traffic-redirector/master/python/TrafficRedirector.py

# support for burp-exceptions - see https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
    import sys
except ImportError:
    pass

from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):

    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # enable for burp-exceptions
        # sys.stdout = callbacks.getStdout()
        
        # set our extension name
        callbacks.setExtensionName("Filter OPTIONS 1")
        
        # register an HTTP listener
        callbacks.registerHttpListener(self)

    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if not messageIsRequest:
            return

        # we need to modify messageInfo which is of type
        # https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html
        # and then return
        # note: we can also modify the associated response here 
        # but we do not care about that in this extension

        # only work on requests coming from proxy
        # see valid values here: https://portswigger.net/burp/extender/api/constant-values.html
        if toolFlag != 4:
            return

        # get request bytes
        requestBytes = messageInfo.getRequest()
        # get request info with https://portswigger.net/burp/extender/api/burp/IRequestInfo.html
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        
        # use getMethod and filter OPTIONS
        if requestInfo.getMethod() != "OPTIONS":
            return

        # add "text/css" to "Accept" header.
        headers = requestInfo.getHeaders()
        # headers is a string list of headers, each header is one line, not a dictionary
        # just add a new header with "Accept: text/css,*/*" and hope for the best
        headers.add("Accept: text/css,*/*")

        # re-create the message
        # we need headers (already here) and body bytes
        # https://portswigger.net/burp/extender/api/burp/IRequestInfo.html#getBodyOffset()
        # get body bytes
        bodyBytes = requestBytes[requestInfo.getBodyOffset():]
        # if we wanted to modify the body, this would be the place

        # build a new message
        # https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html#buildHttpMessage(java.util.List,%20byte[])
        modifiedMessage = self._helpers.buildHttpMessage(headers, bodyBytes)

        # change the request of modifiedMessage
        messageInfo.setRequest(modifiedMessage)

        # and we are done
        return

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass