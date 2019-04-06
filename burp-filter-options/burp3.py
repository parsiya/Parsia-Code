# modified "example traffic redirector" https://raw.githubusercontent.com/PortSwigger/example-traffic-redirector/master/python/TrafficRedirector.py
# idea from https://github.com/pajswigger/filter-options/blob/master/src/filter-options.kt

# the idea
# 1. Identify outgoing OPTIONS requests.
# 2. Inject "Content-Type: text/css; charset=UTF-8"
# 3. Burp HTTP History will think the MIME TYPE of request is CSS
# 4. Now you can hide them all by filtering CSS from the filtering menu

# enable for burp-exceptions - see https://github.com/securityMB/burp-exceptions
# from exceptions_fix import FixBurpExceptions
# import sys

from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):

    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Filter OPTIONS 3")
        
        # register an HTTP listener
        callbacks.registerHttpListener(self)

    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        # here we need to modify messageInfo which is of type
        # https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html
        # and then return
        # odify the response and then use messageInfo.setResponse
        # https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html#setResponse(byte[])
        
        # do not process outgoing requests, we only care about responses
        if messageIsRequest:
            return

        # we only care about requests coming from the Proxy, ignore other tools (e.g. Repeater)
        # see valid values here: https://portswigger.net/burp/extender/api/constant-values.html
        if toolFlag != 4:
            return

        # analyze the request for the response we are currently processing.
        # we need to identify if the HTTP verb is OPTIONS

        # get request bytes
        requestBytes = messageInfo.getRequest()
        # process request with https://portswigger.net/burp/extender/api/burp/IRequestInfo.html
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        # use getMethod to filter non-OPTIONS
        if requestInfo.getMethod() != "OPTIONS":
            return

        # process the response and Inject "Content-Type: text/css; charset=UTF-8"

        # get response bytes
        responseBytes = messageInfo.getResponse()
        # process response
        responseInfo = self._helpers.analyzeResponse(responseBytes)
        
        # get response headers
        responseHeaders = responseInfo.getHeaders()
           
        # just add the duplicate content-type header to response and hope it works, YOLO!
        responseHeaders.add("Content-Type: text/css; charset=UTF-8")
        
        # re-create the response with new headers

        # get response body bytes
        responseBodyBytes = responseBytes[responseInfo.getBodyOffset():]
        # if we wanted to modify the body, this would be the place

        # build a new message
        modifiedMessage = self._helpers.buildHttpMessage(responseHeaders, responseBodyBytes)

        # set the response to this request.
        # we are processing it before it hits the history, it will appear as modified there
        messageInfo.setResponse(modifiedMessage)

        # and we are done
        return

# for burp-exceptions
FixBurpExceptions()



