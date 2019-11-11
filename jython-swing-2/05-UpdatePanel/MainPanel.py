# The converted GUI from NetBeans.

from javax.swing import (JScrollPane, JTable, JPanel, JTextField, JLabel,
                         JTabbedPane, JComboBox, table, BorderFactory,
                         GroupLayout, LayoutStyle, JFrame)
from IssueTable import IssueTable

class MainPanel():
    """Represents the converted frame from NetBeans."""

    # mostly converted generated code
    def __init__(self):
        self.jScrollPane1 = JScrollPane()
        self.jTable1 = JTable()
        self.jPanel1 = JPanel()
        self.labelName = JLabel()
        self.textName = JTextField()
        self.labelSeverity = JLabel()
        self.textSeverity = JTextField()
        self.labelHost = JLabel()
        self.labelPath = JLabel()
        self.textHost = JTextField()
        self.textPath = JTextField()
        self.tabIssue = JTabbedPane()
        self.panelDescription = JPanel()
        self.panelRequest = JPanel()
        self.panelResponse = JPanel()
        self.panelRemediation = JPanel()

        # setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE)

        # setting up the table
        # initial data in the table
        tableData = [
            [3, "Issue3", "Severity3", "Host3", "Path3"],
            [1, "Issue1", "Severity1", "Host1", "Path1"],
            [2, "Issue2", "Severity2", "Host2", "Path2"],
        ]
        tableHeadings = ["#", "Issue Type/Name", "Severity", "Host", "Path"]
        self.jTable1 = IssueTable(tableData, tableHeadings)

        # wrap the table in a scrollpane
        self.jScrollPane1.setViewportView(self.jTable1)

        # top panel containing the table
        from java.awt import Color
        self.jPanel1.setBorder(BorderFactory.createLineBorder(Color(0, 0, 0)))

        # create the labels and textfields
        self.labelName.text = "Issue Type/Name"
        self.textName.text = "Issue Name/Type"
        self.textName.editable = False
        self.textName.setBackground(Color.LIGHT_GRAY)

        self.labelSeverity.text = "Severity"
        self.textSeverity.text = ""
        self.textSeverity.editable = False
        self.textSeverity.setBackground(Color.LIGHT_GRAY)

        self.labelHost.text = "Host"
        self.textHost.text = "Issue Host"
        self.textHost.editable = False
        self.textHost.setBackground(Color.LIGHT_GRAY)

        self.labelPath.text = "Path"
        self.textPath.text = "Issue Path"
        self.textPath.editable = False
        self.textPath.setBackground(Color.LIGHT_GRAY)

        from java.lang import Short
        # description panel
        panelDescriptionLayout = GroupLayout(self.panelDescription)
        self.panelDescription.setLayout(panelDescriptionLayout)
        panelDescriptionLayout.setHorizontalGroup(
            panelDescriptionLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 948, Short.MAX_VALUE)
        )
        panelDescriptionLayout.setVerticalGroup(
            panelDescriptionLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 287, Short.MAX_VALUE)
        )
        self.tabIssue.addTab("Description", self.panelDescription)

        # request tab
        panelRequestLayout = GroupLayout(self.panelRequest)
        self.panelRequest.setLayout(panelRequestLayout)
        panelRequestLayout.setHorizontalGroup(
            panelRequestLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 948, Short.MAX_VALUE)
        )
        panelRequestLayout.setVerticalGroup(
            panelRequestLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 287, Short.MAX_VALUE)
        )
        self.tabIssue.addTab("Request", self.panelRequest)

        # response tab
        panelResponseLayout = GroupLayout(self.panelResponse)
        self.panelResponse.setLayout(panelResponseLayout)
        panelResponseLayout.setHorizontalGroup(
            panelResponseLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 948, Short.MAX_VALUE)
        )
        panelResponseLayout.setVerticalGroup(
            panelResponseLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 287, Short.MAX_VALUE)
        )
        self.tabIssue.addTab("Response", self.panelResponse)

        # remediation tab
        panelRemediationLayout = GroupLayout(self.panelRemediation)
        self.panelRemediation.setLayout(panelRemediationLayout)
        panelRemediationLayout.setHorizontalGroup(
            panelRemediationLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 948, Short.MAX_VALUE)
        )
        panelRemediationLayout.setVerticalGroup(
            panelRemediationLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGap(0, 287, Short.MAX_VALUE)
        )
        self.tabIssue.addTab("Remediation", self.panelRemediation)

        # jpanel1?
        jPanel1Layout = GroupLayout(self.jPanel1)
        self.jPanel1.setLayout(jPanel1Layout)
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(jPanel1Layout.createSequentialGroup()
                          .addContainerGap()
                          .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addGroup(jPanel1Layout.createSequentialGroup()
                                              .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                                        .addComponent(self.labelHost)
                                                        .addComponent(self.labelSeverity)
                                                        .addComponent(self.labelName))
                                              .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                              .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                                        .addComponent(self.textName)
                                                        .addGroup(jPanel1Layout.createSequentialGroup()
                                                                  .addComponent(self.textSeverity, GroupLayout.PREFERRED_SIZE, 98, GroupLayout.PREFERRED_SIZE)
                                                                  .addGap(0, 0, Short.MAX_VALUE))
                                                        .addGroup(jPanel1Layout.createSequentialGroup()
                                                                  .addComponent(self.textHost, GroupLayout.PREFERRED_SIZE, 330, GroupLayout.PREFERRED_SIZE)
                                                                  .addGap(18, 18, 18)
                                                                  .addComponent(self.labelPath)
                                                                  .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                                  .addComponent(self.textPath))))
                                    .addComponent(self.tabIssue))
                          .addContainerGap())
        )

        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(jPanel1Layout.createSequentialGroup()
                          .addContainerGap()
                          .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(self.labelName)
                                    .addComponent(self.textName, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                          .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                          .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(self.labelSeverity)
                                    .addComponent(self.textSeverity, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                          .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                          .addGroup(jPanel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                    .addComponent(self.labelHost)
                                    .addComponent(self.labelPath)
                                    .addComponent(self.textHost, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                    .addComponent(self.textPath, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                          .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                          .addComponent(self.tabIssue)
                          .addContainerGap())
        )

        # create the main panel
        self.panel = JPanel()
        layout = GroupLayout(self.panel)
        self.panel.setLayout(layout)
        layout.setAutoCreateGaps(True)

        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                          .addContainerGap()
                          .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addComponent(self.jPanel1, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(self.jScrollPane1))
                          .addContainerGap())
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                          .addContainerGap()
                          .addComponent(self.jScrollPane1, GroupLayout.PREFERRED_SIZE, 119, GroupLayout.PREFERRED_SIZE)
                          .addGap(18, 18, 18)
                          .addComponent(self.jPanel1, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                          .addContainerGap())
        )

    # end of converted code


# create "global" panel
mainPanel = MainPanel()
