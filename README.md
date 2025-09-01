# PhishGuardAI-AI-Powered-Email-Phishing-Detection-
PhishGuardAI is a desktop application designed to help users detect phishing emails using advanced AI models. The tool provides an intuitive interface for previewing, scanning, and analyzing emails, leveraging both local (offline) and cloud-based AI models for maximum flexibility and privacy.


## Key Features
Email Preview & Management:
Users can view, organize, and manage emails from their inbox, including attachments and sent items.

### Phishing Detection (Offline & Online):

Offline: Integrates with Ollama and the Phi4-Mini model for local, private AI analysis without internet dependency.
Online: Supports OpenAI’s GPT models via API for cloud-based analysis.
Detailed AI Reports:
Each email scan provides a clear label (Phishing/Not Phishing), a detailed reasoning paragraph, and concise summaries in English and Italian.

### User-Friendly GUI:
* Built with PyQt5 and PyQtWebEngine for a modern, responsive desktop experience.

### Installer & Portability:
* Delivered as a Windows installer (setup.exe) that bundles all dependencies and models, allowing easy installation and use on any PC.

#### Technical Stack
* Python 3.x
*  PyQt5 / PyQtWebEngine (GUI)
* Ollama (Local LLM integration)
* OpenAI API (Cloud LLM integration)
* dotenv (Environment/config management)
* PyInstaller (EXE packaging)
* Inno Setup (Windows installer creation)

### How It Works
### Email Loading:
The app loads emails from local files or connects to IMAP servers (e.g., Gmail).

### Phishing Analysis:

Offline: Uses Ollama’s Phi4-Mini model (bundled with the installer) for instant, private analysis.
Online: Optionally sends emails to OpenAI’s GPT-3.5 Turbo for deeper analysis.
Results Display:
Users receive a clear verdict, detailed reasoning, and multilingual summaries for each email.

### Easy Installation:
The installer sets up all files, models, and shortcuts—no manual setup required.

