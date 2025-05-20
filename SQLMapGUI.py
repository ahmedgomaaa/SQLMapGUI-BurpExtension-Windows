# -*- coding: utf-8 -*-  
from burp import IBurpExtender, IContextMenuFactory, ITab  
from java.util import ArrayList  
from javax.swing import (  
    JPanel, JButton, JCheckBox, JScrollPane, JTextPane,  
    JLabel, BoxLayout, JTable, JMenuItem, ListSelectionModel, JSplitPane,  
    JTextField, JComboBox  
)  
from javax.swing.table import DefaultTableModel  
from javax.swing.text import SimpleAttributeSet, StyleConstants  
from java.awt import Color, Font, BorderLayout, GridLayout  
import subprocess  
import threading  
import time  
import os  
import sys
import java.io.File as JavaFile
  
class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):  
    def registerExtenderCallbacks(self, callbacks):  
        self._callbacks = callbacks  
        self._helpers = callbacks.getHelpers()  
        callbacks.setExtensionName("SQLMap GUI")  
  
        self.saved_requests = []  
        self.proc = None  
  
        # Use Java's temp directory for saving files
        self.logs_dir = str(JavaFile.createTempFile("burp_sqlmap_", "_dir").getParent())
        # Create a logs directory if it doesn't exist
        self.logs_dir = os.path.join(self.logs_dir, "burp_sqlmap_logs")
        if not os.path.exists(self.logs_dir):
            try:
                os.makedirs(self.logs_dir)
            except:
                # If we can't create the directory, fall back to system temp
                self.logs_dir = str(JavaFile.createTempFile("sqlmap_", ".tmp").getParent())
        
        self.panel = JPanel(BorderLayout())  
  
        self.req_table_model = DefaultTableModel(["Saved Requests"], 0)  
        self.req_table = JTable(self.req_table_model)  
        self.req_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)  
        table_scroll = JScrollPane(self.req_table)  
  
        self.options_panel = JPanel(GridLayout(0, 3, 5, 5))  
        self.options = []  
  
        def add_option(label, takes_value=False, default_value=""):  
            box = JCheckBox(label)  
            field = JTextField(default_value) if takes_value else None  
            self.options.append((box, field))  
            self.options_panel.add(box)  
            self.options_panel.add(field if field else JPanel())  
  
        def add_dropdown(label, values):  
            box = JCheckBox(label)  
            dropdown = JComboBox(values)  
            self.options.append((box, dropdown))  
            self.options_panel.add(box)  
            self.options_panel.add(dropdown)  
  
        add_option("--risk", True, "3")  
        add_option("--level", True, "5")  
        add_option("--tables")  
        add_option("--dump")  
        add_option("--columns")  
        add_option("--current-user")  
        add_option("--current-db")  
        add_option("--passwords")  
        add_option("--dbs")  
        add_option("--dump-all")  
        add_option("--banner")  
        add_option("--flush-session")  
        add_option("--forms")  
        add_option("--crawl", True)  
        add_dropdown("--threads", [str(i) for i in range(1, 11)])  
        add_option("--delay", True)  
        add_dropdown("--technique", ["", "B", "T", "E", "U", "S", "Q", "A"])  
        add_option("--proxy", True, "http://127.0.0.1:8080")  
        add_option("--random-agent")  
        add_option("--read-file", True)  
        add_option("--file-write", True)  
        add_option("--file-dest", True)  
        add_option("--tamper", True, "space2comment")  
        add_option("--dbms", True)  
        add_option("-D", True)  
        add_option("-T", True)  
        add_option("-C", True)  
  
        self.output_pane = JTextPane()  
        self.output_pane.setEditable(False)  
        self.output_pane.setFont(Font("Monospaced", Font.BOLD, 16))  
        output_scroll = JScrollPane(self.output_pane)  
  
        self.run_button = JButton("Run SQLMap", actionPerformed=self.run_sqlmap)  
        self.stop_button = JButton("Stop", actionPerformed=self.kill_sqlmap)  
        self.button_panel = JPanel()  
        self.button_panel.add(self.run_button)  
        self.button_panel.add(self.stop_button)  
  
        self.left_panel = JPanel(BorderLayout())  
        top_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, self.options_panel)  
        top_split.setResizeWeight(0.5)  
        self.left_panel.add(top_split, BorderLayout.CENTER)  
  
        self.right_panel = JPanel(BorderLayout())  
        self.right_panel.add(output_scroll, BorderLayout.CENTER)  
        self.right_panel.add(self.button_panel, BorderLayout.SOUTH)  
  
        split_main = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.left_panel, self.right_panel)  
        split_main.setResizeWeight(0.35)  
        self.panel.add(split_main, BorderLayout.CENTER)  
  
        callbacks.customizeUiComponent(self.panel)  
        callbacks.addSuiteTab(self)  
        callbacks.registerContextMenuFactory(self)
        
        # Log extension startup information
        self.append_output("[+] SQLMap GUI Extension loaded\n", "green")
        self.append_output("[+] SQLMap path: F:\\sqlmap_last\\sqlmap.py\n", "gray")
        self.append_output("[+] Logs directory: {}\n".format(self.logs_dir), "gray")
  
    def getTabCaption(self):  
        return "SQLMap GUI"  
  
    def getUiComponent(self):  
        return self.panel  
  
    def createMenuItems(self, invocation):  
        menu = ArrayList()  
        menu.add(JMenuItem("Send to SQLMap", actionPerformed=lambda x: self.save_request(invocation)))  
        return menu  
  
    def save_request(self, invocation):  
        reqs = invocation.getSelectedMessages()  
        if not reqs:
            self.append_output("[-] No request selected.\n", "red")
            return  
        
        try:
            request_info = self._helpers.analyzeRequest(reqs[0])  
            headers = request_info.getHeaders()  
            body = self._helpers.bytesToString(reqs[0].getRequest()[request_info.getBodyOffset():])  
            timestamp = int(time.time())  
            
            # Use the logs directory for saving request files
            filename = os.path.join(self.logs_dir, "sqlmap-{}.req".format(timestamp))
            
            # Debug output
            self.append_output("[*] Saving request to: {}\n".format(filename), "gray")
            
            # Use binary mode to avoid encoding issues on Windows
            with open(filename, "wb") as f:  
                for h in headers:  
                    f.write((h + "\r\n").encode('utf-8'))  
                f.write(("\r\n" + body).encode('utf-8'))
            
            # Verify file was created
            if os.path.exists(filename):
                self.saved_requests.append(filename)  
                self.req_table_model.addRow([filename])  
                self.append_output("[+] Saved: %s\n" % filename, "green")
            else:
                self.append_output("[-] Failed to save request file: %s\n" % filename, "red")
                
        except Exception as e:
            self.append_output("[!] Error saving request: %s\n" % str(e), "red")
  
    def run_sqlmap(self, _):  
        row = self.req_table.getSelectedRow()  
        if row == -1:  
            self.append_output("[-] No request selected.\n", "red")  
            return  
        
        try:
            filename = self.req_table_model.getValueAt(row, 0)  
            if not os.path.exists(filename):
                self.append_output("[-] Request file not found: %s\n" % filename, "red")
                return
                
            # Modified for Windows - use specific SQLMap path with quotes to handle spaces
            sqlmap_path = "F:\\sqlmap_last\\sqlmap.py"
            
            # For Windows, we need to use a command string with proper quoting
            cmd_str = 'python "{}" -r "{}" --batch'.format(sqlmap_path, filename)
            cmd = [cmd_str]
            
            # Add options
            for checkbox, field in self.options:  
                if checkbox.isSelected():  
                    option = checkbox.getText()
                    cmd_str += " " + option
                    if field and hasattr(field, "getText") and field.getText():  
                        cmd_str += " " + field.getText()
                    elif field and hasattr(field, "getSelectedItem") and field.getSelectedItem():  
                        cmd_str += " " + field.getSelectedItem()
            
            self.append_output("[*] Running: %s\n" % cmd_str, "gray")  
            
            def execute():  
                try:  
                    # Use shell=True for Windows command execution
                    self.proc = subprocess.Popen(  
                        cmd_str,  
                        stdout=subprocess.PIPE,  
                        stderr=subprocess.STDOUT,  
                        shell=True,
                        universal_newlines=True
                    )  
                    
                    while True:  
                        line = self.proc.stdout.readline()  
                        if not line:  
                            break  
                        decoded = line.strip()
                        if "vulnerable" in decoded:  
                            self.append_output(decoded + "\n", "green")  
                        elif "[INFO]" in decoded:  
                            self.append_output(decoded + "\n", "gray")  
                        elif "[WARNING]" in decoded:  
                            self.append_output(decoded + "\n", "orange")  
                        elif "[CRITICAL]" in decoded or "[ERROR]" in decoded:  
                            self.append_output(decoded + "\n", "red")  
                        else:  
                            self.append_output(decoded + "\n", "gray")  
                    
                    self.proc.stdout.close()  
                    self.proc = None  
                except Exception as e:  
                    self.append_output("[!] Exception: %s\n" % str(e), "red")  
            
            threading.Thread(target=execute).start()
            
        except Exception as e:
            self.append_output("[!] Error running SQLMap: %s\n" % str(e), "red")
  
    def kill_sqlmap(self, _):  
        if self.proc and self.proc.poll() is None:  
            try:
                self.proc.terminate()  
                self.append_output("[!] SQLMap process terminated.\n", "red")  
            except:
                self.append_output("[!] Failed to terminate SQLMap process.\n", "red")
            finally:
                self.proc = None  
        else:  
            self.append_output("[!] No active scan to kill.\n", "orange")  
  
    def append_output(self, text, color_name):  
        try:
            document = self.output_pane.getDocument()  
            style = SimpleAttributeSet()  
            
            if color_name == "red":  
                StyleConstants.setForeground(style, Color.RED)  
            elif color_name == "green":  
                StyleConstants.setForeground(style, Color.GREEN)  
            elif color_name == "orange":  
                StyleConstants.setForeground(style, Color(255, 165, 0))  
            elif color_name == "gray":  
                StyleConstants.setForeground(style, Color.GRAY)  
            
            document.insertString(document.getLength(), text, style)  
            self.output_pane.setCaretPosition(document.getLength())
        except Exception as e:
            print("Error in append_output: " + str(e))
