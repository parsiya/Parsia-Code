# 0-decoder/extension.py
from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

# Parsia: modified "custom editor tab" https://github.com/PortSwigger/example-custom-editor-tab/.

# Parsia: for burp-exceptions - see https://github.com/securityMB/burp-exceptions
from exceptions_fix import FixBurpExceptions
import sys

# Parsia: import helpers from library
from library import *

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # Parsia: obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        # Parsia: changed the extension name
        callbacks.setExtensionName("Example Crypto(graphy)")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

        # Parsia: for burp-exceptions
        sys.stdout = callbacks.getStdout()
        
    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return CryptoTab(self, controller, editable)
        
# 
# class implementing IMessageEditorTab
#

class CryptoTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        # Parsia: Burp helpers object
        self.helpers = extender._helpers

        # create an instance of Burp's text editor, to display our decrypted data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        # Parsia: tab title
        return "Decrypted"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        return True
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()
        
    def setMessage(self, content, isRequest):
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        # Parsia: if tab has content
        else:
            # get the body
            body = getBody(content, isRequest, self.helpers)
            # base64 decode the body
            decodedBody = decode64(body, self.helpers)
            # set the body as text of message box
            self._txtInput.setText(decodedBody)
            # this keeps the message box edit value to whatever it was
            self._txtInput.setEditable(self._editable)
        
        # remember the displayed content
        self._currentMessage = content
    
    def getMessage(self):
        # determine whether the user modified the data
        if self._txtInput.isTextModified():
            # Parsia: if text has changed, encode it and make it the new body of the message
            modified = self._txtInput.getText()
            encodedModified = encode64(modified, self.helpers)
            
            # Parsia: create a new message with the new body and return that
            info = getInfo(self._currentMessage, True, self.helpers)
            headers = info.getHeaders()
            return self.helpers.buildHttpMessage(headers, encodedModified)
        else:
            # Parsia: if nothing is modified, return the current message so nothing gets updated
            return self._currentMessage

# Parsia: for burp-exceptions
FixBurpExceptions()