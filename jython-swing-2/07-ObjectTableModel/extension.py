# Update the panel with selected row's data.

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
        self.callbacks = callbacks

        # support for burp-exceptions
        try:
            sys.stdout = callbacks.getStdout()
        except:
            pass

        # set our extension name
        callbacks.setExtensionName("07-ObjectTableModel")

        # add the tab to Burp's UI
        callbacks.addSuiteTab(self)

    # implement ITab
    # https://portswigger.net/burp/extender/api/burp/ITab.html
    # two methods must be implemented.

    def getTabCaption(self):
        """Burp uses this method to obtain the caption that should appear on the
        custom tab when it is displayed. Returns a string with the tab name.
        """
        return "07-ObjectTableModel"

    def getUiComponent(self):
        """Burp uses this method to obtain the component that should be used as
        the contents of the custom tab when it is displayed.
        Returns a awt.Component.
        """
        # GUI happens here
        # setting up the table
        # initial data in the table
        tableData = [
            # [3, "Issue3", "Severity3", "Host3", "Path3"],
            [1, "Issue1", "Severity1", "Host1", "Path1", "Description1",
             "Remediation1", "Request1", "Response1"],
            # [2, "Issue2", "Severity2", "Host2", "Path2"],
        ]
        # tableHeadings = ["#", "Issue Type/Name", "Severity", "Host", "Path"]
        from IssueTable import IssueTable
        from Issue import Issue
        issues = list()
        for it in tableData:
            tmpIssue = Issue(index=it[0], name=it[1], severity=it[2],host=it[3],
                             path=it[4], description=it[5], remediation=it[6],
                             request=it[7], response=it[8])
            issues.append(tmpIssue)

        table = IssueTable(issues)
        import MainPanel
        MainPanel.burpPanel = MainPanel.MainPanel(self.callbacks, table)

        # do we need to call self.callbacks.customizeUiComponent here?
        return MainPanel.burpPanel.panel

# support for burp-exceptions
try:
    FixBurpExceptions()
except:
    pass