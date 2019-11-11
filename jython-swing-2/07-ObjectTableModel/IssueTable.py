# Represents a custom Issue table.

from javax.swing import JTable
from javax.swing.table import AbstractTableModel
from java.awt.event import MouseListener

from Issue import Issue
import java.lang


class IssueTableModel(AbstractTableModel):
    """Represents the extension's custom issue table. Extends the
    AbstractTableModel to make it readonly."""
    # column names
    columnNames = ["#", "Issue Type/Name", "Severity", "Host", "Path"]
    # column classes

    columnClasses = [java.lang.Integer, java.lang.String, java.lang.String,
                     java.lang.String, java.lang.String]

    # list to hold all the issues
    # if this does not work use an ArrayList
    # from java.util import ArrayList
    # issues = ArrayList() - issues.add(whatever)
    issues = list()

    def __init__(self, issues=None):
        """Create an issue table model and populate it (if applicable)."""
        self.issues = issues

    def getColumnCount(self):
        # type: () -> int
        """Returns the number of columns in the table model."""
        return len(self.columnNames)

    def getRowCount(self):
        # type: () -> int
        """Returns the number of rows in the table model."""
        return len(self.issues)

    def getValueAt(self, row, column):
        # type: (int, int) -> object
        """Returns the value at the specified row and column."""
        if row < self.getRowCount() and column < self.getColumnCount():
            # is this going to come back and bite us in the back because we
            # are ignoring the hidden fields?
            issue = self.issues[row]
            if column == 0:
                return issue.index
            if column == 1:
                return issue.name
            if column == 2:
                return issue.severity
            if column == 3:
                return issue.host
            if column == 4:
                return issue.path
            return None

    # interface implemented, adding utility methods

    def getColumnName(self, index):
        # type: (int) -> str
        """Returns the name of the table column."""
        if 0 <= index < self.getColumnCount():
            return self.columnNames[index]
        else:
            return "Invalid Column Index: " + str(index)

    def getColumnClass(self, index):
        # type: (int) -> object
        """Returns the class of the table column."""
        if 0 <= index < len(self.columnClasses):
            return self.columnClasses[index]
        return java.lang.Object

    def isCellEditable(self, row, column):
        # type: (int, int) -> bool
        """Returns True if cells are editable."""
        # make all rows and columns uneditable.
        return False

    def getIssue(self, index):
        # type: (int) -> Issue
        """Returns the issue object at index."""
        if 0 <= index < len(self.issues):
            return self.issues[index]
        return self.issues[0]

    def addIssue(self, issue):
        # type: (Issue) -> ()
        """Adds the issue to the list of issues."""
        # let's worry about manual indexing later?
        self.issues.append(issue)
        self.fireTableDataChanged()

    def removeIssue(self, index):
        # type: (int) -> ()
        """Removes the issue at index from the list of issues."""
        if 0 <= index < len(self.issues):
            del self.issues[index]
            self.fireTableDataChanged()
        # otherwise do nothing.


class IssueTableMouseListener(MouseListener):
    """Custom mouse listener to differentiate between single and double-clicks.
    """
    def getClickedIndex(self, event):
        """Returns the value of the first column of the table row that was
        clicked. This is not the same as the row index because the table
        can be sorted."""
        # get the event source, the table in this case.
        tbl = event.getSource()
        # get the clicked row
        row = tbl.convertRowIndexToModel(tbl.getSelectedRow())
        # get the first value of clicked row
        return tbl.getValueAt(row, 0)
        # return event.getSource.getValueAt(event.getSource().getSelectedRow(), 0)

    def getClickedRow(self, event):
        """Returns the complete clicked row."""
        tbl = event.getSource()
        mdl = tbl.getModel()
        row = tbl.convertRowIndexToModel(tbl.getSelectedRow())
        assert isinstance(mdl, IssueTableModel)
        return mdl.getIssue(row)
        # return tbl.getModel().getDataVector().elementAt()

    def mousePressed(self, event):
        # print "mouse pressed", event.getClickCount()
        pass

    def mouseReleased(self, event):
        # print "mouse released", event.getClickCount()
        pass

    # event.getClickCount() returns the number of clicks.
    def mouseClicked(self, event):
        if event.getClickCount() == 1:
            # print "single-click. clicked index:", self.getClickedIndex(event)
            rowData = self.getClickedRow(event)
            assert isinstance(rowData, Issue)

            # let's see if we can modify the panel
            # import burpPanel to modify it
            from MainPanel import burpPanel, MainPanel
            assert isinstance(burpPanel, MainPanel)
            burpPanel.textName.text = rowData.name
            burpPanel.textSeverity.text = rowData.severity
            burpPanel.textHost.text = rowData.host
            burpPanel.textPath.text = rowData.path
            burpPanel.textAreaDescription.text = rowData.description
            burpPanel.textAreaRemediation.text = rowData.remediation
            burpPanel.panelRequest.setMessage(rowData.getRequest(), True)
            burpPanel.panelResponse.setMessage(rowData.getResponse(), False)

        if event.getClickCount() == 2:
            # open the dialog to edit
            # print "double-click. clicked index:", self.getClickedIndex(event)
            # print "double-click"
            tbl = event.getSource()
            mdl = tbl.getModel()
            assert isinstance(mdl, IssueTableModel)
            curRow = mdl.getRowCount()
            newRow = str(curRow+1)
            issue = Issue(index=newRow, name="Issue"+newRow,
                          severity="Severity"+newRow, host="Host"+newRow,
                          path="Path"+newRow, description="Description"+newRow,
                          remediation="Remediation"+newRow,
                          request="Request"+newRow, response="Response"+newRow)
            tbl.addRow(issue)

    def mouseEntered(self, event):
        pass

    def mouseExited(self, event):
        pass


class IssueTable(JTable):
    """Issue table."""

    def __init__(self, issues):
        # set the table model
        model = IssueTableModel(issues)
        self.setModel(model)
        self.setAutoCreateRowSorter(True)
        # disable the reordering of columns
        self.getTableHeader().setReorderingAllowed(False)
        # assign panel to a field
        self.addMouseListener(IssueTableMouseListener())

    def addRow(self, issue):
        """Add a new row to the tablemodel."""
        self.getModel().addIssue(issue)

    # solution to resize column width automagically
    # https://stackoverflow.com/a/17627497