"""
    Burp utility module for Python Burp extensions.
    Author: Parsia Hakimian
    License: GPLv3

    # Usage
    1. Add it as a Python Burp module and use `from burputils import *`.
        For more info see:
        https://parsiya.net/blog/2018-12-19-python-utility-modules-for-burp-extensions/
    2. Copy the file to the same path as your extension and use 
        `from burputils import *`.
        * The second file does not have to be loaded in Burp, it just needs to 
            be in the same path.
    3. Copy/paste used code into your extension.

    Please see README for details.
"""


class BurpUtils:
    """Helpers for Burp Python extensions"""

    def __init__(self, callbackHelper):
        """
        Set IExtensionHelpers
        
        Set with callbacks.getHelpers() in registerExtenderCallbacks.
        """
        self.burpHelper = callbackHelper
    
    def getInfoFromBytes(self, isRequest, rawBytes):
        """
        Process request or response from raw bytes.

        Returns IRequestInfo or IResponseInfo respectively.
        
        Use getInfo instead if you have access to an IHttpRequestResponse object.
        It allows you to use all methods like IRequestInfo.getUrl() later.
        """
        if isRequest:
            return self.burpHelper.analyzeRequest(rawBytes)
        else:
            return self.burpHelper.analyzeResponse(rawBytes)
    
    def getInfo(self, isRequest, requestResponse):
        """
        Process request or response from IHttpRequestResponse.

        Returns IRequestInfo or IResponseInfo respectively.
        This method is preferable to getInfoFromBytes.
        """
        if isRequest:
            return self.burpHelper.analyzeRequest(requestResponse)
        else:
            return self.burpHelper.analyzeResponse(requestResponse.getResponse())
    
    def getBodyFromBytes(self, isRequest, rawBytes):
        """Returns body bytes from a reqest or response bytes."""
        info = self.getInfoFromBytes(isRequest, rawBytes)
        return rawBytes[info.getBodyOffset()]
    
    def getBody(self, isRequest, requestResponse):
        """Returns body bytes from an IHttpRequestResponse object."""
        info = self.getInfo(isRequest, requestResponse)

        if isRequest:
            return requestResponse.getRequest()[info.getBodyOffset():]
        else:
            return requestResponse.getResponse()[info.getBodyOffset():]

    def getHeaders(self, info):
        """Returns request/response headers in a Headers object."""
        hdr = Headers()
        rawHdr = info.getHeaders()
        hdr.importRaw(rawHdr)
        return hdr
    
    def setRequestResponse(self, isRequest, message, requestResponse):
        """
        Set the request or response for an IHttpRequestResponse object.
        
        Args:
        
        * isRequest (bool): True if message is a request. False for response.
        * message (byte[]): Raw bytes containing the request or response.
        Usually comes from buildHttpMessage.
        * requestResponse (IHttpRequestResponse): RequestResponse to be modified.
        """
        # If isRequest is True, use setRequest. Otherwise, setResponse.
        if isRequest:
            requestResponse.setRequest(message)
        else:
            requestResponse.setResponse(message)


class Headers:
    """
    Represents HTTP headers.

    Burp returns headers as an ArrayList<string>, this class converts it into
    a dict(list).
    
    Note: This class treates headers as case-sensitive and does not check for
    duplicate values. Duplicate headers will be repeated
    """

    def __init__(self):
        """Create the header collection."""
        from collections import defaultdict
        self._hdr = defaultdict(list)
        # the first header line coming from Burp is special.
        # it's the first line of the request ("GET /whatever HTTP/1.1")
        # which has a different structure than other headers.
        self._first = ""

    def get(self, header):
        """
        Returns a list containing the header's value(s).
        
        Returns None if header does not exist in _hdr.
        """
        # this is functionally equivalent to "self._hdr[header]" but we can
        # change the default return value from None later if needed (e.g. to "").
        return self._hdr.get(header, None)
    
    def add(self, header, value):
        """
        Adds header:value to _hdr.

        If header exists, value is added to the list under that header.
        """
        self._hdr[header].append(value)
        
    def remove(self, header):
        """Removes header from _hdr."""
        # pop removes header from the dictionary and returns its value.
        # providing the default value None, prevents exceptions if header does
        # not exist in the dictionary.
        temp = self._hdr.pop(header, None)
    
    def overwrite(self, header, value):
        """
        Overwrites the value of a header.

        If the header does not exist, it will be added.
        If you want duplicate headers, use add instead.
        """
        # if it exists, remove it
        if header in self._hdr:
            self.remove(header)
        
        # add header
        self.add(header, value)

    def importRaw(self, rawHeader):
        """Deserializes the Burp header list into a Headers object."""
        # set the first line, e.g. "GET /whatever HTTP/1.1".
        self._first = rawHeader[0]
        # set the rest
        for h in rawHeader[1:]:
            # separate header and value
            spl = h.split(":", 1)
            if len(spl) == 2:
                self.add(spl[0], spl[1].strip())
            else:
                # if the line does not contain ":", add all of it
                self.add(spl[0], None)

    def exportRaw(self):
        """
        Serializes the header back to the Burp format.
        Returns a java.util.ArrayList(string).

        A string list with one header on each line.
        Adds multiple values as duplicate headers.
        """
        import java.util.ArrayList as ArrayList
        lst = ArrayList()
        # add the first line
        lst.add(self._first)
        # iterate through headers
        for header in self._hdr:
            values = self._hdr[header]
            if values is None:
                # if header does not have a value, just add the header
                lst.add(header)
                continue
            
            # iterate through header values and add one line for each value
            for val in values:
                lst.add("{}: {}".format(header, val))
        return lst
