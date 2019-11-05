# Burp extension to test JScrollPane.
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
        callbacks.setExtensionName("Test JScrollPane")
        
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
        from javax.swing import (JPanel, JSplitPane, JLabel, JList,
            JScrollPane, ListSelectionModel)
        from java.awt import BorderLayout
        panel = JPanel(BorderLayout())

        # create a list and then JList out of it.
        colors = ["red", "orange", "yellow", "green", "cyan", "blue", "pink",
            "magenta", "gray","zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"]

        def listSelect(event):
            """Add the selected index to the label."""
            label1.text += "-" + colors[list1.selectedIndex]

        # create a list and assign the valueChanged
        list1 = JList(colors, valueChanged=listSelect)
        list1.selectionMode = ListSelectionModel.SINGLE_SELECTION

        # create splitpane - horizontal split
        label1 = JLabel("right pane")
        spl = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(list1),
            label1)
        
        panel.add(spl)
        return panel

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass