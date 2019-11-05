# Burp extension to test StyledDocument and custom styles.

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
        callbacks.setExtensionName("Test StyledDocument")
        
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
        from javax.swing import (JPanel, JSplitPane, JList, JTextPane,
            JScrollPane, ListSelectionModel, JLabel, JTabbedPane, JEditorPane)
        from java.awt import BorderLayout
        panel = JPanel(BorderLayout())

        # create a list and then JList out of it.
        colors = ["red", "orange", "yellow", "green", "cyan", "blue", "pink",
            "magenta", "gray","zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"]

        # create a list - the list is not used in this example
        list1 = JList(colors)
        list1.selectionMode = ListSelectionModel.SINGLE_SELECTION

        # create a StyledDocument for tab 1
        from javax.swing.text import DefaultStyledDocument
        doc = DefaultStyledDocument()
        # create a JTextPane from doc
        tab1 = JTextPane(doc)
        tab1.editable = False

        # we can add more styles
        # new styles can be a child of previous styles
        # our first style is a child of the default style
        from javax.swing.text import StyleContext, StyleConstants
        defaultStyle = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE)

        # returns a Style
        regular = doc.addStyle("regular", defaultStyle)
        StyleConstants.setFontFamily(defaultStyle, "Times New Roman")

        # make different styles from regular
        style1 = doc.addStyle("italic", regular)
        StyleConstants.setItalic(style1, True)

        style1 = doc.addStyle("bold", regular)
        StyleConstants.setBold(style1, True)

        style1 = doc.addStyle("small", regular)
        StyleConstants.setFontSize(style1, 10)

        style1 = doc.addStyle("large", regular)
        StyleConstants.setFontSize(style1, 16)

        # insert text
        doc.insertString(doc.length, "This is regular\n", doc.getStyle("regular"))
        doc.insertString(doc.length, "This is italic\n", doc.getStyle("italic"))
        doc.insertString(doc.length, "This is bold\n", doc.getStyle("bold"))
        doc.insertString(doc.length, "This is small\n", doc.getStyle("small"))
        doc.insertString(doc.length, "This is large\n", doc.getStyle("large"))

        # create the tabbedpane
        tabs = JTabbedPane()

        tabs.addTab("Tab 1", tab1)

        # create splitpane - horizontal split
        spl = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(list1),
            tabs)
        
        panel.add(spl)
        return panel

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass