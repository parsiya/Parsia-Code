# Burp extension to test adding a tab with extra stuff in it.
# somewhat based on https://laconicwolf.com/2019/02/07/burp-extension-python-tutorial-encode-decode-hash/

# support for burp-exceptions - see https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
    import sys
except ImportError:
    pass


from burp import IBurpExtender
# needed for tab
from burp import ITab

class BurpExtender(IBurpExtender, ITab):
    # implement IBurpExtender

    # set everything up
    def registerExtenderCallbacks(self, callbacks):

        # get helpers - not needed here.
        # self.helpers = callbacks.getHelpers()

        # support for burp-exceptions
        try:
            sys.stdout = callbacks.getStdout()
        except:
            pass
        
        # set our extension name
        callbacks.setExtensionName("Test ITab")
        
        # add the tab to Burp's UI
        callbacks.addSuiteTab(self)

    # implement ITab
    # https://portswigger.net/burp/extender/api/burp/ITab.html
    # two methods must be implemented.

    def getTabCaption(self):
        """Burp uses this method to obtain the caption that should appear on the
        custom tab when it is displayed. Returns a string with the tab name.
        """
        return "Example Tab"
    
    def getUiComponent(self):
        """Burp uses this method to obtain the component that should be used as
        the contents of the custom tab when it is displayed.
        Returns a awt.Component.
        """
        # GUI happens here
        from javax.swing import JPanel, JButton
        from java.awt import BorderLayout
        panel = JPanel(BorderLayout())

        # create buttons
        def btn1Click(event):
            """What happens when button 1 is clicked."""
            # btn1.setText("Clicked")
            # this is more Jythonic(?)
            btn1.text = "Clicked"
            return

        btn1 = JButton("Button 1", actionPerformed=btn1Click)

        # add buttons to the panel
        panel.add(btn1, BorderLayout.PAGE_START)

        return panel

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass