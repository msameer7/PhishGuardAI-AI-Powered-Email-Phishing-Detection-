import subprocess
import json
import os
import requests
from dotenv import load_dotenv

def analyze_emails_with_ollama(model="phi4-mini", json_path="emails.json"):
    try:
        with open(json_path, "r", encoding="utf-8") as file:
            emails = json.load(file)

        results = []

        for idx, email in enumerate(emails, start=1):
            prompt = f"""
    You are a smart email security analyst.

    Analyze the following email and decide if it's 'Phishing' or 'Not Phishing'.

    Respond in exactly this format:
    Label: <Phishing or Not Phishing>
    Reason: <A detailed 200 words paragraph explaining your decision, including key indicators and context.>
    Summary (English): <Concised 50 words summary in a paragraph in English>
    Summary (Italian): <Concised 50words summary in a paragraph Italian>
    From: {email.get('from','')}
    Subject: {email.get('subject','')}
    Body: {email.get('body','')}
            """

            try:
                process = subprocess.run(
                    ["ollama", "run", model],
                    input=prompt.encode('utf-8'),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                if process.returncode != 0:
                    result_text = f"⚠️ Error: {process.stderr.decode('utf-8')}"
                else:
                    result_text = process.stdout.decode('utf-8').strip()
            except Exception as e:
                result_text = f"⚠️ Exception: {str(e)}"

            results.append({
                "from": email.get("from",""),
                "subject": email.get("subject",""),
                "result": result_text
            })

        # Save results to the same file that was passed
        with open(json_path, "w", encoding="utf-8") as outfile:
            json.dump(results, outfile, indent=2)

        return True, f"✅ Successfully scanned {len(emails)} emails using {model}."

    except Exception as e:
        return False, f"❌ Failed to process emails: {str(e)}"

def analyze_emails_with_openai(json_path="emails.json"):
    load_dotenv()
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

    HEADERS = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://yourdomain.com",
        "X-Title": "Email Security Test App"
    }

    API_URL = "https://openrouter.ai/api/v1/chat/completions"

    try:
        with open(json_path, "r", encoding="utf-8") as file:
            emails = json.load(file)

        results = []

        for idx, email in enumerate(emails, start=1):
            prompt = f"""
You are a smart email security analyst.

Analyze the following email and decide if it's 'Phishing' or 'Not Phishing'.

Respond in exactly this format:
Label: <Phishing or Not Phishing>
Reason: <A detailed 1500 words paragraph explaining your decision, including key indicators and context.>
Summary (English): <Concised 200 words summary in a paragraph in English>
Summary (Italian): <Concised 200 words summary in a paragraph Italian>
From: {email.get('from','')}
Subject: {email.get('subject','')}
Body: {email.get('body','')}
            """

            payload = {
                "model": "openai/gpt-3.5-turbo",
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            }

            try:
                response = requests.post(API_URL, headers=HEADERS, json=payload)
                response.raise_for_status()
                result = response.json()
                result_text = result["choices"][0]["message"]["content"].strip()
            except Exception as e:
                result_text = f"⚠️ Error during classification: {str(e)}"

            results.append({
                "from": email.get("from",""),
                "subject": email.get("subject",""),
                "result": result_text
            })

        # Save results to the same file that was passed
        with open(json_path, "w", encoding="utf-8") as outfile:
            json.dump(results, outfile, indent=2)

        return True, f"✅ Successfully scanned {len(emails)} emails."

    except Exception as e:
        return False, f"❌ Failed to process emails: {str(e)}"