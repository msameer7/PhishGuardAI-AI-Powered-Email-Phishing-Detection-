from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys
import json
import base64
import mimetypes
import re
import imaplib
import time
from pathlib import Path
from email import encoders, policy
from email.parser import BytesParser
import smtplib
from email.message import EmailMessage


from PyQt5.QtCore import Qt, QUrl, QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QListWidget, QSplitter, QTextEdit,
    QPushButton, QFileDialog, QLabel, QHBoxLayout, QToolBar, QAction,
    QLineEdit, QCheckBox, QStackedWidget, QProgressBar, QTabWidget, QMessageBox, QDialog, QComboBox
)
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEnginePage, QWebEngineProfile, QWebEngineSettings
from PyQt5.QtWebEngineCore import QWebEngineUrlRequestInterceptor

import os
from dotenv import load_dotenv

# ---------------- CONFIG ----------------
IMAP_SERVER = "imap.gmail.com"
MAILBOX = "INBOX"
LIMIT = 25
CREDENTIALS_FILE = "credentials.json"
OUTPUT_FILE = "emails.json"
SENT_FILE = "sent_emails.json"
MAX_ATTACHMENT_SIZE_MB = 20
# ----------------------------------------

def parse_raw_mime(raw_str):
    if isinstance(raw_str, str):
        raw_bytes = raw_str.encode('utf-8', errors='surrogateescape')
    else:
        raw_bytes = raw_str
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    return msg

def extract_best_html_and_attachments(item):
    attachments = []
    headers = {}
    html = None
    text = None
    if 'raw' in item:
        msg = parse_raw_mime(item['raw'])
        headers['subject'] = str(msg.get('subject', ''))
        headers['from'] = str(msg.get('from', ''))
        headers['to'] = str(msg.get('to', ''))
        headers['date'] = str(msg.get('date', ''))
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get_content_disposition() or "")
                if ctype == 'text/html' and html is None:
                    try:
                        html = part.get_content()
                    except Exception:
                        html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                elif ctype == 'text/plain' and text is None:
                    try:
                        text = part.get_content()
                    except Exception:
                        text = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                else:
                    payload = part.get_payload(decode=True)
                    if payload is not None:
                        filename = part.get_filename() or ''
                        cid = None
                        if part['Content-ID']:
                            cid = part['Content-ID'].strip('<>')
                        attachments.append({
                            'filename': filename,
                            'content': payload,
                            'content_id': cid,
                            'mime': part.get_content_type()
                        })
        else:
            ctype = msg.get_content_type()
            if ctype == 'text/html':
                try:
                    html = msg.get_content()
                except Exception:
                    html = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="ignore")
            elif ctype == 'text/plain':
                try:
                    text = msg.get_content()
                except Exception:
                    text = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="ignore")
    else:
        html = item.get('html')
        text = item.get('text')
        headers['subject'] = item.get('subject', '')
        headers['from'] = item.get('from', '')
        headers['to'] = item.get('to', '')
        headers['date'] = item.get('date', '')
        for a in item.get('attachments', []):
            content = a.get('content')
            if isinstance(content, str):
                try:
                    content_bytes = base64.b64decode(content)
                except Exception:
                    content_bytes = content.encode('utf-8', errors='surrogateescape')
            else:
                content_bytes = content
            attachments.append({
                'filename': a.get('filename', ''),
                'content': content_bytes,
                'content_id': a.get('content_id'),
                'mime': a.get('mime', mimetypes.guess_type(a.get('filename',''))[0] or 'application/octet-stream')
            })
    if not html and text:
        html = "<pre style='white-space:pre-wrap;font-family:monospace'>{}</pre>".format(escape_html(text))
    if not html:
        html = "<i>(no HTML or text found)</i>"
    return html, headers, attachments

def escape_html(s):
    import html as _html
    return _html.escape(s)

def inline_cid_images(html, attachments):
    cid_map = {}
    for a in attachments:
        if a.get('content_id'):
            mime = a.get('mime') or 'application/octet-stream'
            b64 = base64.b64encode(a['content']).decode('ascii')
            cid_map[a['content_id']] = f"data:{mime};base64,{b64}"
    def repl(m):
        cid = m.group(1)
        return f'src="{cid_map.get(cid, "cid:" + cid)}"'
    new_html = re.sub(r'src=["\']cid:([^"\']+)["\']', repl, html, flags=re.IGNORECASE)
    return new_html

class SimpleInterceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, allow_external=False):
        super().__init__()
        self.allow_external = allow_external

    def interceptRequest(self, info):
        url = info.requestUrl()
        scheme = url.scheme().lower()
        if scheme in ('data', 'file', 'about', 'blob', 'chrome'):
            return
        if scheme in ('http', 'https'):
            if not self.allow_external:
                info.redirect(QUrl("data:text/plain,blocked"))

class ExternalLinkPage(QWebEnginePage):
    def acceptNavigationRequest(self, url, _type, isMainFrame):
        if _type == QWebEnginePage.NavigationTypeLinkClicked:
            QDesktopServices.openUrl(url)
            return False
        return super().acceptNavigationRequest(url, _type, isMainFrame)

class FetchWorker(QThread):
    finished = pyqtSignal(list, str)

    def __init__(self, email_user, email_pass, limit=LIMIT):
        super().__init__()
        self.email_user = email_user
        self.email_pass = email_pass
        self.limit = limit

    def run(self):
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(self.email_user, self.email_pass)
            mail.select(MAILBOX)
            result, data = mail.search(None, "ALL")
            if result != "OK":
                mail.logout()
                self.finished.emit([], "IMAP search failed")
                return
            mail_ids = data[0].split()
            latest_ids = mail_ids[-self.limit:]
            emails = []
            for num in reversed(latest_ids):
                result, msg_data = mail.fetch(num, "(RFC822)")
                if result != "OK" or not msg_data:
                    continue
                raw_msg = msg_data[0][1]
                raw_str = raw_msg.decode("utf-8", errors="surrogateescape")
                emails.append({"raw": raw_str})
            mail.logout()
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(emails, f, indent=2, ensure_ascii=False)
            self.finished.emit(emails, None)
        except Exception as e:
            self.finished.emit([], str(e))

class PhishingResultDialog(QDialog):
    def __init__(self, results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Phishing Detection Results")
        self.setFixedSize(750, 600)
        layout = QVBoxLayout(self)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet("""
            QTextEdit {
                font-size: 14px;
                font-family: 'Segoe UI', Arial, sans-serif;
                background: #f9f9f9;
                border: 2px solid #e0e0e0;
                border-radius: 12px;
                padding: 16px;
                color: #222;
            }
        """)
        layout.addWidget(self.result_text)

        self.results = results
        self.show_results()

    def show_results(self):
        display = ""
        for r in self.results:
            subject = r.get("subject", "")
            result = r.get("result", "")
            label = ""
            reason = ""
            summary_en = ""
            summary_it = ""
            lines = result.splitlines()
            for line in lines:
                if line.lower().startswith("label:"):
                    label = line.partition(":")[2].strip()
                elif line.lower().startswith("reason:"):
                    reason = line.partition(":")[2].strip()
                elif line.lower().startswith("summary (english):"):
                    summary_en = line.partition(":")[2].strip()
                elif line.lower().startswith("summary (italian):"):
                    summary_it = line.partition(":")[2].strip()
            display += (
                f"<div style='margin-bottom:18px;'>"
                f"<span style='font-size:16px;font-weight:bold;color:#0078d7;'>Subject: {escape_html(subject)}</span><br><br>"
                f"<span style='font-size:13px;'><b>Label:</b> {escape_html(label)}</span><br>"
                f"<span style='font-size:13px;'><b>Reason:</b> {escape_html(reason)}</span><br>"
                f"<span style='font-size:13px;'><b>Summary (English):</b> {escape_html(summary_en)}</span><br>"
                f"<span style='font-size:13px;'><b>Summary (Italian):</b> {escape_html(summary_it)}</span>"
                f"</div>"
            )
        self.result_text.setHtml(display)

class EmailPreviewer(QWidget):
    def __init__(self, emails=None, stack=None):
        super().__init__()
        self.setWindowTitle("Email Previewer (PyQt + QtWebEngine)")
        self.resize(800, 600)
        self.emails_raw = emails or []
        self.sent_emails = self.load_sent_emails()
        self.parsed_cache = []
        self.sent_cache = []
        self.allow_external = False
        self.js_enabled = False
        self.stack = stack

        self.tabs = QTabWidget()
        self.inbox_widget = QWidget()
        self.sent_widget = QWidget()

        self.left_list = QListWidget()
        self.left_list.currentRowChanged.connect(self.show_email)
        self.sent_list = QListWidget()
        self.sent_list.currentRowChanged.connect(self.show_sent_email)

        self.compose_btn = QPushButton("✉️ Compose")
        self.compose_btn.clicked.connect(self.compose_email)

        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_inbox)

        self.phishing_btn = QPushButton("🛡️ Phishing")
        self.phishing_btn.clicked.connect(self.open_phishing_dialog)

        toolbar = QToolBar()
        self.toggle_images_action = QAction("Allow external images", self)
        self.toggle_images_action.setCheckable(True)
        self.toggle_images_action.toggled.connect(self.toggle_external_resources)
        toolbar.addAction(self.toggle_images_action)

        self.toggle_js_action = QAction("Enable JavaScript", self)
        self.toggle_js_action.setCheckable(True)
        self.toggle_js_action.toggled.connect(self.toggle_js)
        toolbar.addAction(self.toggle_js_action)

        self.signout_action = QAction("🚪 Sign Out", self)
        self.signout_action.triggered.connect(self.sign_out)
        toolbar.addAction(self.signout_action)

        self.profile = QWebEngineProfile.defaultProfile()
        self.interceptor = SimpleInterceptor(allow_external=self.allow_external)
        try:
            self.profile.setUrlRequestInterceptor(self.interceptor)
        except Exception:
            try:
                self.profile.setRequestInterceptor(self.interceptor)
            except Exception:
                pass

        self.web = QWebEngineView()
        self.web.setPage(ExternalLinkPage(self.profile, self.web))
        self.web.page().settings().setAttribute(QWebEngineSettings.JavascriptEnabled, self.js_enabled)

        self.attach_layout = QHBoxLayout()
        self.attach_label = QLabel("Attachments: ")
        self.attach_layout.addWidget(self.attach_label)
        self.attach_buttons = []

        inbox_layout = QVBoxLayout(self.inbox_widget)
        inbox_layout.addWidget(QLabel("Inbox"))
        inbox_layout.addWidget(self.left_list)
        row = QHBoxLayout()
        row.addWidget(self.compose_btn)
        row.addWidget(self.refresh_btn)
        row.addWidget(self.phishing_btn)
        inbox_layout.addLayout(row)

        sent_layout = QVBoxLayout(self.sent_widget)
        sent_layout.addWidget(QLabel("Sent"))
        sent_layout.addWidget(self.sent_list)

        self.tabs.addTab(self.inbox_widget, "Inbox")
        self.tabs.addTab(self.sent_widget, "Sent")

        right_layout = QVBoxLayout()
        right_layout.addWidget(toolbar)
        self.header_text = QTextEdit()
        self.header_text.setReadOnly(True)
        self.header_text.setMaximumHeight(140)
        right_layout.addWidget(self.header_text)
        right_layout.addWidget(self.web)
        attach_row = QWidget()
        attach_row.setLayout(self.attach_layout)
        right_layout.addWidget(attach_row)
        right_widget = QWidget()
        right_widget.setLayout(right_layout)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.tabs)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(1, 3)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(splitter)

        if self.emails_raw:
            self.load_from_data(self.emails_raw)
        self.load_sent_tab()

    def load_sent_emails(self):
        try:
            with open(SENT_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def save_sent_email(self, email_dict):
        self.sent_emails.append(email_dict)
        with open(SENT_FILE, "w", encoding="utf-8") as f:
            json.dump(self.sent_emails, f, indent=2, ensure_ascii=False)
        self.load_sent_tab()

    def load_sent_tab(self):
        self.sent_cache = []
        self.sent_list.clear()
        for i, item in enumerate(self.sent_emails):
            html, headers, attachments = extract_best_html_and_attachments(item)
            self.sent_cache.append((headers, html, attachments))
            subj = headers.get('subject') or f"Sent Email {i+1}"
            to = headers.get('to') or ''
            date = headers.get('date') or ''
            display = f"{subj}\nTo: {to} — {date}"
            self.sent_list.addItem(display)

    def show_sent_email(self, idx):
        if idx < 0 or idx >= len(self.sent_cache):
            return
        headers, html, attachments = self.sent_cache[idx]
        header_text = (
            f"Subject: {headers.get('subject','')}\n"
            f"To: {headers.get('to','')}\n"
            f"Date: {headers.get('date','')}"
        )
        self.header_text.setPlainText(header_text)
        self.web.setHtml(html)
        self.clear_attachments_ui()
        if attachments:
            for a in attachments:
                name = a.get('filename') or (a.get('content_id') or "attachment")
                btn = QPushButton(name)
                btn.clicked.connect(lambda _, att=a: self.save_attachment(att))
                self.attach_layout.addWidget(btn)
                self.attach_buttons.append(btn)
        else:
            lbl = QLabel("(no attachments)")
            self.attach_layout.addWidget(lbl)
            self.attach_buttons.append(lbl)

    def compose_email(self):
        dlg = QWidget()
        dlg.setWindowTitle("Compose Email")
        layout = QVBoxLayout(dlg)
        to_in = QLineEdit()
        to_in.setPlaceholderText("To")
        subj_in = QLineEdit()
        subj_in.setPlaceholderText("Subject")
        body_in = QTextEdit()
        body_in.setPlaceholderText("Body")
        attach_btn = QPushButton("Attach File")
        attach_label = QLabel("")
        send_btn = QPushButton("Send")
        layout.addWidget(QLabel("To:"))
        layout.addWidget(to_in)
        layout.addWidget(QLabel("Subject:"))
        layout.addWidget(subj_in)
        layout.addWidget(QLabel("Body:"))
        layout.addWidget(body_in)
        layout.addWidget(attach_btn)
        layout.addWidget(attach_label)
        layout.addWidget(send_btn)

        attachments = []

        def attach_file():
            files, _ = QFileDialog.getOpenFileNames(dlg, "Attach files", "", "All Files (*)")
            attach_label.setText("")
            attachments.clear()
            for file_path in files:
                try:
                    size_mb = Path(file_path).stat().st_size / (1024 * 1024)
                    if size_mb > MAX_ATTACHMENT_SIZE_MB:
                        attach_label.setText(f"File too large: {Path(file_path).name} (>20MB)")
                        continue
                    with open(file_path, "rb") as f:
                        content = f.read()
                    attachments.append({
                        "filename": Path(file_path).name,
                        "content": base64.b64encode(content).decode("utf-8"),
                        "content_id": None,
                        "mime": mimetypes.guess_type(file_path)[0] or "application/octet-stream"
                    })
                    attach_label.setText(attach_label.text() + f"Attached: {Path(file_path).name}\n")
                except Exception as e:
                    attach_label.setText(attach_label.text() + f"Error: {str(e)}\n")

        attach_btn.clicked.connect(attach_file)

        def send():
            to = to_in.text().strip()
            subj = subj_in.text().strip()
            body = body_in.toPlainText()
            if not to or not subj or not body:
                QMessageBox.warning(dlg, "Error", "All fields required!")
                return

            try:
                # --- Load credentials (saved earlier by your login) ---
                with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                    creds = json.load(f)
                email_user = creds["email"]
                email_pass = creds["password"]  # Gmail App Password

            # --- Build MIME message ---
                msg = MIMEMultipart()
                msg["From"] = email_user
                msg["To"] = to
                msg["Subject"] = subj
                msg.attach(MIMEText(body, "plain"))

            # Add attachments (if any)
                for att in attachments:
                    part = MIMEBase(*att["mime"].split("/", 1))
                    part.set_payload(base64.b64decode(att["content"]))
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", f'attachment; filename="{att["filename"]}"')
                    msg.attach(part)

            # --- Send via Gmail SMTP ---
                server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
                server.login(email_user, email_pass)
                server.sendmail(email_user, to, msg.as_string())
                server.quit()

            # --- Also save locally in "Sent" ---
                email_dict = {
                    "subject": subj,
                    "to": to,
                    "date": time.strftime("%Y-%m-%d %H:%M"),
                    "html": body,
                    "attachments": attachments.copy()
                }
                self.save_sent_email(email_dict)

                QMessageBox.information(self, "Sent", "Email sent successfully!")
                dlg.close()

            except Exception as e:
                QMessageBox.critical(dlg, "Error", f"Failed to send email:\n{str(e)}")

        send_btn.clicked.connect(send)
        dlg.setLayout(layout)
        dlg.setFixedSize(400, 500)
        dlg.show()

    def load_from_data(self, emails):
        self.emails_raw = emails
        self.parsed_cache = []
        self.left_list.clear()
        self.load_and_prepare()

    def load_and_prepare(self):
        for i, item in enumerate(self.emails_raw):
            html, headers, attachments = extract_best_html_and_attachments(item)
            html = inline_cid_images(html, attachments)
            self.parsed_cache.append((headers, html, attachments))
            subj = headers.get('subject') or f"Email {i+1}"
            frm = headers.get('from') or ''
            date = headers.get('date') or ''
            display = f"{subj}\n{frm} — {date}"
            self.left_list.addItem(display)
        if self.left_list.count() > 0:
            self.left_list.setCurrentRow(0)

    def clear_attachments_ui(self):
        for w in self.attach_buttons:
            self.attach_layout.removeWidget(w)
            w.deleteLater()
        self.attach_buttons = []

    def save_attachment(self, attachment):
        fname = attachment.get('filename') or "attachment"
        content = attachment.get('content') or b""
        if isinstance(content, str):
            try:
                content = base64.b64decode(content)
            except Exception:
                content = content.encode('utf-8', errors='surrogateescape')
        path, _ = QFileDialog.getSaveFileName(self, "Save attachment", fname)
        if path:
            with open(path, "wb") as f:
                f.write(content)

    def show_email(self, idx):
        if idx < 0 or idx >= len(self.parsed_cache):
            return
        headers, html, attachments = self.parsed_cache[idx]
        header_text = (
            f"Subject: {headers.get('subject','')}\n"
            f"From: {headers.get('from','')}\n"
            f"To: {headers.get('to','')}\n"
            f"Date: {headers.get('date','')}"
        )
        self.header_text.setPlainText(header_text)
        self.web.setHtml(html)
        self.clear_attachments_ui()
        if attachments:
            for a in attachments:
                name = a.get('filename') or (a.get('content_id') or "attachment")
                btn = QPushButton(name)
                btn.clicked.connect(lambda _, att=a: self.save_attachment(att))
                self.attach_layout.addWidget(btn)
                self.attach_buttons.append(btn)
        else:
            lbl = QLabel("(no attachments)")
            self.attach_layout.addWidget(lbl)
            self.attach_buttons.append(lbl)

    def toggle_external_resources(self, checked):
        self.allow_external = bool(checked)
        self.interceptor.allow_external = self.allow_external
        self.web.reload()

    def toggle_js(self, checked):
        self.js_enabled = bool(checked)
        self.web.page().settings().setAttribute(QWebEngineSettings.JavascriptEnabled, self.js_enabled)
        self.web.reload()

    def sign_out(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("Sign Out")
        msg.setText("How do you want to sign out?")
        casual_btn = msg.addButton("Casual Sign Out", QMessageBox.AcceptRole)
        perm_btn = msg.addButton("Permanent Sign Out", QMessageBox.DestructiveRole)
        msg.setStandardButtons(QMessageBox.Cancel)
        msg.setDefaultButton(casual_btn)
        msg.exec_()

        if msg.clickedButton() == perm_btn:
            try:
                Path(CREDENTIALS_FILE).unlink()
            except Exception:
                pass
            QMessageBox.information(self, "Signed Out", "You have permanently signed out. Credentials removed.")
            if self.stack:
                self.stack.setCurrentIndex(0)
        elif msg.clickedButton() == casual_btn:
            if self.stack:
                self.stack.setCurrentIndex(0)

    def refresh_inbox(self):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                creds = json.load(f)
                email_user = creds.get("email", "")
                email_pass = creds.get("password", "")
        except Exception:
            QMessageBox.warning(self, "Error", "Credentials not found. Please sign in again.")
            return

        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("Refreshing...")

        def on_finished(emails, error):
            self.refresh_btn.setEnabled(True)
            self.refresh_btn.setText("🔄 Refresh")
            if error:
                QMessageBox.warning(self, "Error", "Failed to fetch emails:\n" + str(error))
                return
            self.load_from_data(emails)

        self.worker = FetchWorker(email_user, email_pass, limit=LIMIT)
        self.worker.finished.connect(on_finished)
        self.worker.start()

    def open_phishing_dialog(self):
        dlg = QWidget()
        dlg.setWindowTitle("Select Emails for Phishing Detection")
        layout = QVBoxLayout(dlg)
        info_lbl = QLabel("Select up to 5 emails to scan for phishing:")
        info_lbl.setStyleSheet("font-size:16px;font-weight:bold;color:#0078d7;")
        email_list = QListWidget()
        email_list.setSelectionMode(QListWidget.MultiSelection)
        for i, (headers, _, _) in enumerate(self.parsed_cache):
            subj = headers.get('subject', f"Email {i+1}")
            frm = headers.get('from', '')
            display = f"{subj}\n{frm}"
            email_list.addItem(display)
        layout.addWidget(info_lbl)
        layout.addWidget(email_list)
        detect_btn = QPushButton("🛡️ Detect Phishing")
        detect_btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d7;
                color: white;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                padding: 10px 20px;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:pressed {
                background-color: #004377;
            }
        """)
        layout.addWidget(detect_btn)
        dlg.setLayout(layout)
        dlg.setFixedSize(500, 400)

        def on_detect():
            selected = email_list.selectedIndexes()
            if not selected or len(selected) > 5:
                QMessageBox.warning(dlg, "Limit", "Select up to 5 emails only.")
                return
            selected_emails = []
            for idx in selected:
                headers, _, _ = self.parsed_cache[idx.row()]
                selected_emails.append({
                    "from": headers.get("from", ""),
                    "subject": headers.get("subject", ""),
                    "body": headers.get("subject", "")
                })

            model_dlg = QMessageBox(dlg)
            model_dlg.setWindowTitle("Choose Detection Method")
            model_dlg.setText("Select phishing detection method:")
            llama_btn = model_dlg.addButton("Offline Llama", QMessageBox.AcceptRole)
            openai_btn = model_dlg.addButton("OpenAI (Online)", QMessageBox.AcceptRole)
            model_dlg.setStandardButtons(QMessageBox.Cancel)
            model_dlg.exec_()

            if model_dlg.clickedButton() == llama_btn:
                ok, msg = self.run_phishing_offline(selected_emails)
            elif model_dlg.clickedButton() == openai_btn:
                ok, msg = self.run_phishing_online(selected_emails)
            else:
                return

            temp_path = "selected_emails.json"
            try:
                with open(temp_path, "r", encoding="utf-8") as f:
                    results = json.load(f)
            except Exception:
                results = []

            result_dialog = PhishingResultDialog(results, parent=self)
            result_dialog.exec_()

        detect_btn.clicked.connect(on_detect)
        dlg.show()

    def run_phishing_offline(self, emails):
        temp_path = "selected_emails.json"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(emails, f, indent=2)
        try:
            from detecting_phishing import analyze_emails_with_ollama
            ok, msg = analyze_emails_with_ollama(json_path=temp_path)
            with open(temp_path, "r", encoding="utf-8") as f:
                results = json.load(f)
            result_str = "\n".join([f"{r['subject']}\n{r['result']}" for r in results])
            return ok, result_str
        except Exception as e:
            return False, f"Error: {str(e)}"

    def run_phishing_online(self, emails):
        temp_path = "selected_emails.json"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(emails, f, indent=2)
        try:
            from detecting_phishing import analyze_emails_with_openai
            ok, msg = analyze_emails_with_openai(json_path=temp_path)
            with open(temp_path, "r", encoding="utf-8") as f:
                results = json.load(f)
            result_str = "\n".join([f"{r['subject']}\n{r['result']}" for r in results])
            return ok, result_str
        except Exception as e:
            return False, f"Error: {str(e)}"

class LoginFrame(QWidget):
    def __init__(self, stack):
        super().__init__()
        self.stack = stack
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        card = QWidget()
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(40, 40, 40, 40)
        card_layout.setSpacing(20)
        card.setStyleSheet("""
            QWidget {
                background-color: #f9f9f9;
                border: 2px solid #e0e0e0;
                border-radius: 12px;
            }
        """)
        title = QLabel("🔐 Sign in with Gmail")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #333;")
        title.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(title)
        self.email_in = QLineEdit()
        self.email_in.setPlaceholderText("Gmail address")
        self.email_in.setFixedHeight(40)
        self.email_in.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border-radius: 8px;
                border: 1px solid #ccc;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #0078d7;
            }
        """)
        card_layout.addWidget(self.email_in)
        self.pass_in = QLineEdit()
        self.pass_in.setPlaceholderText("App Password")
        self.pass_in.setEchoMode(QLineEdit.Password)
        self.pass_in.setFixedHeight(40)
        self.pass_in.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border-radius: 8px;
                border: 1px solid #ccc;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #0078d7;
            }
        """)
        card_layout.addWidget(self.pass_in)
        self.rem_checkbox = QCheckBox("Remember Me")
        self.rem_checkbox.setStyleSheet("font-size: 13px; color: #555;")
        card_layout.addWidget(self.rem_checkbox)
        btn = QPushButton("Sign In")
        btn.setFixedHeight(40)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #0078d7;
                color: white;
                border-radius: 8px;
                font-size: 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:pressed {
                background-color: #004377;
            }
        """)
        btn.clicked.connect(self.on_signin)
        card_layout.addWidget(btn)
        main_layout.addWidget(card, alignment=Qt.AlignCenter)
        self.setLayout(main_layout)
        self.load_credentials()

    def load_credentials(self):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.email_in.setText(data.get("email",""))
                self.pass_in.setText(data.get("password",""))
                if data.get("remember", False):
                    self.rem_checkbox.setChecked(True)
                else:
                    self.rem_checkbox.setChecked(False)
        except FileNotFoundError:
            self.email_in.setText("")
            self.pass_in.setText("")
            self.rem_checkbox.setChecked(False)

    def save_credentials(self, email, password):
        if self.rem_checkbox.isChecked():
            with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
                json.dump({"email": email, "password": password, "remember": True}, f, indent=2)
        else:
            try:
                Path(CREDENTIALS_FILE).unlink()
            except Exception:
                pass

    def on_signin(self):
        email_user = self.email_in.text().strip()
        email_pass = self.pass_in.text().strip()
        if not email_user or not email_pass:
            return
        self.save_credentials(email_user, email_pass)
        loading = self.stack.widget(1)
        loading.start_fetch(email_user, email_pass)
        self.stack.setCurrentIndex(1)

class LoadingFrame(QWidget):
    def __init__(self, stack):
        super().__init__()
        self.stack = stack
        self.worker = None
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        card = QWidget()
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(40, 40, 40, 40)
        card_layout.setSpacing(20)
        card.setStyleSheet("""
            QWidget {
                background-color: #f9f9f9;
                border: 2px solid #e0e0e0;
                border-radius: 12px;
            }
        """)
        self.label = QLabel("🔄 Logging in and Fetching Emails...")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 16px; color: #333;")
        card_layout.addWidget(self.label)
        self.progress = QProgressBar()
        self.progress.setFixedHeight(25)
        self.progress.setRange(0, 0)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #aaa;
                border-radius: 8px;
                text-align: center;
                font-size: 13px;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #0078d7;
                border-radius: 8px;
            }
        """)
        card_layout.addWidget(self.progress)
        main_layout.addWidget(card, alignment=Qt.AlignCenter)
        self.setLayout(main_layout)

    def start_fetch(self, email_user, email_pass):
        self.label.setText("🔄 Logging in and Fetching Emails...")
        self.progress.setRange(0, 0)
        self.worker = FetchWorker(email_user, email_pass, limit=LIMIT)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

    def on_finished(self, emails, error):
        if error:
            self.label.setText("❌ Error: " + str(error))
            self.progress.setRange(0, 1)
            QTimer.singleShot(2000, lambda: self.stack.setCurrentIndex(0))
            return
        previewer = self.stack.widget(2)
        previewer.load_from_data(emails)
        self.stack.setCurrentIndex(2)

class MainApp(QStackedWidget):
    def __init__(self):
        super().__init__()
        self.login = LoginFrame(self)
        self.loading = LoadingFrame(self)
        self.previewer = EmailPreviewer([], stack=self)
        self.addWidget(self.login)
        self.addWidget(self.loading)
        self.addWidget(self.previewer)
        self.setCurrentIndex(0)

def main():
    app = QApplication(sys.argv)
    window = MainApp()
    window.setWindowTitle("PhishGuardAI - Email Previewer")
    window.resize(1200, 800)
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()