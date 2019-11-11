# Update the table in realtime.

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
        callbacks.setExtensionName("06-UpdateTable")

        # add the tab to Burp's UI
        callbacks.addSuiteTab(self)

    # implement ITab
    # https://portswigger.net/burp/extender/api/burp/ITab.html
    # two methods must be implemented.

    def getTabCaption(self):
        """Burp uses this method to obtain the caption that should appear on the
        custom tab when it is displayed. Returns a string with the tab name.
        """
        return "06-UpdateTable"

    def getUiComponent(self):
        """Burp uses this method to obtain the component that should be used as
        the contents of the custom tab when it is displayed.
        Returns a awt.Component.
        """
        # GUI happens here
        # setting up the table
        # initial data in the table
        tableData = [
            [3, "Issue3", "Severity3", "Host3", "Path3"],
            [1, "Issue1", "Severity1", "Host1", "Path1"],
            [2, "Issue2", "Severity2", "Host2", "Path2"],
        ]
        tableHeadings = ["#", "Issue Type/Name", "Severity", "Host", "Path"]
        from IssueTable import IssueTable
        table = IssueTable(tableData, tableHeadings)
        import MainPanel
        MainPanel.burpPanel = MainPanel.MainPanel(table)

        table.addRow([4, "Issue4", "Severity4", "Host4", "Path4"])

        return MainPanel.burpPanel.panel

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass