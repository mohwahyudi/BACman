from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import (JPanel, JTextArea, JScrollPane, JButton, JTable, 
                         JSplitPane, SwingUtilities)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, Color
import threading

# Custom renderer to color table rows based on status codes
class CustomTableCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        # Call the superclass method to get the default component
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        
        try:
            # Get status codes from the model for the current row
            # Column indices: 3 for Original Status, 4 for Test Status
            original_status = int(table.getModel().getValueAt(row, 3))
            test_status = int(table.getModel().getValueAt(row, 4))

            # Reset background and foreground for all rows
            c.setBackground(Color.WHITE)
            c.setForeground(Color.BLACK)

            # Rule 1: High risk (potential BAC) - e.g., original was forbidden, now it's OK
            if original_status != 200 and test_status == 200:
                c.setBackground(Color(255, 204, 204)) # Light Red
            # Rule 2: Medium risk (potential IDOR) - both users can access the same resource
            elif original_status == 200 and test_status == 200:
                c.setBackground(Color(255, 255, 204)) # Light Yellow
            
            # Override selection color
            if isSelected:
                c.setBackground(table.getSelectionBackground())
                c.setForeground(table.getSelectionForeground())

        except Exception as e:
            # In case of parsing errors, use default colors
            c.setBackground(Color.WHITE)
            c.setForeground(Color.BLACK)
            
        return c

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("BACman")

        # UI Components
        # Add "Original Status" column
        self.log_table_model = DefaultTableModel(["ID", "Method", "URL", "Original Status", "Test Status", "Original Length", "Test Length"], 0)
        self.log_table = JTable(self.log_table_model)
        
        # Apply the custom renderer for row highlighting
        renderer = CustomTableCellRenderer()
        for i in range(self.log_table.getColumnCount()):
            self.log_table.getColumnModel().getColumn(i).setCellRenderer(renderer)

        log_scroll_pane = JScrollPane(self.log_table)

        self.session_area = JTextArea("Cookie: your_cookie_here\nAuthorization: Bearer your_token_here")
        session_scroll_pane = JScrollPane(self.session_area)
        
        self.toggle_button = JButton("Activate", actionPerformed=self.toggle_activation)
        
        config_panel = JPanel(BorderLayout())
        config_panel.add(session_scroll_pane, BorderLayout.CENTER)
        config_panel.add(self.toggle_button, BorderLayout.SOUTH)

        self.main_panel = JSplitPane(JSplitPane.VERTICAL_SPLIT, config_panel, log_scroll_pane)
        self.main_panel.setResizeWeight(0.3)

        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)
        
        self.active = False
        self.request_id = 0

        print("BACman extension loaded.")
        print("Go to the BACman tab to configure the second session header(s).")

    def getTabCaption(self):
        return "BACman"

    def getUiComponent(self):
        return self.main_panel

    def toggle_activation(self, event):
        if self.active:
            self.active = False
            self.toggle_button.setText("Activate")
        else:
            self.active = True
            self.toggle_button.setText("Deactivate")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.active or not messageIsRequest:
            return
        
        # Only process requests from tools where a user is actively testing
        if toolFlag in [self._callbacks.TOOL_PROXY, self._callbacks.TOOL_REPEATER, self._callbacks.TOOL_INTRUDER]:
            thread = threading.Thread(target=self.check_bac, args=(messageInfo,))
            thread.start()

    def check_bac(self, messageInfo):
        self.request_id += 1
        current_request_id = self.request_id

        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = list(request_info.getHeaders())
        
        # Get headers from text area, supporting multiple lines
        session_headers_text = self.session_area.getText()
        session_headers = [h.strip() for h in session_headers_text.split('\n') if ':' in h]
        
        header_names_to_replace = [h.split(':', 1)[0].lower() for h in session_headers]

        # Filter out original headers that will be replaced
        new_headers = [h for h in headers if h.split(':', 1)[0].lower() not in header_names_to_replace]
        # Add the new headers
        new_headers.extend(session_headers)
        
        body_bytes = messageInfo.getRequest()[request_info.getBodyOffset():]
        
        new_request_bytes = self._helpers.buildHttpMessage(new_headers, body_bytes)
        
        http_service = messageInfo.getHttpService()
        new_request_response = self._callbacks.makeHttpRequest(http_service, new_request_bytes)
        
        # Get original response info
        original_response = messageInfo.getResponse()
        original_response_info = self._helpers.analyzeResponse(original_response) if original_response else None
        original_status_code = original_response_info.getStatusCode() if original_response_info else 0
        original_length = len(original_response) if original_response else 0

        # Get test response info
        test_response = new_request_response.getResponse() if new_request_response else None
        test_response_info = self._helpers.analyzeResponse(test_response) if test_response else None
        test_status_code = test_response_info.getStatusCode() if test_response_info else 0
        test_length = len(test_response) if test_response else 0

        # Update UI on the Event Dispatch Thread
        def update_table():
            self.log_table_model.addRow([
                str(current_request_id),
                request_info.getMethod(),
                str(request_info.getUrl()),
                str(original_status_code),
                str(test_status_code),
                str(original_length),
                str(test_length)
            ])
        SwingUtilities.invokeLater(update_table)