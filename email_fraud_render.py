#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
メール詐欺検知プログラム - Render版
環境変数から設定を読み込み、Renderで動作します
"""

from flask import Flask, render_template_string, jsonify, request
import imaplib
import email
from email.header import decode_header
import re
from datetime import datetime
import json
import threading
import os

app = Flask(__name__)

# 環境変数から設定を読み込み
GMAIL_ADDRESS = os.environ.get('GMAIL_ADDRESS', '')
GMAIL_PASSWORD = os.environ.get('GMAIL_PASSWORD', '')
YAHOO_ADDRESS = os.environ.get('YAHOO_ADDRESS', '')
YAHOO_PASSWORD = os.environ.get('YAHOO_PASSWORD', '')
MAX_EMAILS = int(os.environ.get('MAX_EMAILS', '20'))

# 正規ドメインリスト
LEGITIMATE_DOMAINS = {
    'amazon': ['amazon.co.jp', 'amazon.com', 'amazon-corp.com', 'email.amazon.co.jp', 'email.amazon.com'],
    'rakuten': ['rakuten.co.jp', 'rakuten-card.co.jp', 'mail.rakuten.co.jp', 'rakuten-bank.co.jp', 'ac.rakuten-bank.co.jp', 'rakuten-drive.com'],
    'paypal': ['paypal.com', 'paypal.co.jp', 'email.paypal.com'],
    'apple': ['apple.com', 'icloud.com', 'email.apple.com'],
    'google': ['google.com', 'gmail.com', 'youtube.com'],
    'microsoft': ['microsoft.com', 'outlook.com', 'live.com'],
    'yahoo': ['yahoo.co.jp', 'yahoo.com', 'mail.yahoo.co.jp'],
    'bank': ['mufg.jp', 'smbc.co.jp', 'mizuhobank.co.jp', 'jp-bank.japanpost.jp', 'bk.mufg.jp', 'direct.bk.mufg.jp', 'paypay-bank.co.jp', 'cc.paypay-bank.co.jp'],
    'paypay': ['paypay-bank.co.jp', 'cc.paypay-bank.co.jp'],
    'sagawa': ['sagawa-exp.co.jp', 'send.sagawa-exp.co.jp'],
    'yamato': ['kuronekoyamato.co.jp', 'yamatofinancial.jp', 'transport.yamato-hd.co.jp'],
    'kuroneko': ['kuronekoyamato.co.jp', 'yamatofinancial.jp', 'transport.yamato-hd.co.jp'],
    'yupack': ['post.japanpost.jp', 'japanpost.jp', 'mail.japanpost.jp'],
    'japanpost': ['post.japanpost.jp', 'japanpost.jp', 'mail.japanpost.jp', 'jp-bank.japanpost.jp'],
    'etc': ['smile-etc.jp', 'etc-meisai.jp'],
    'etcマイレージ': ['smile-etc.jp', 'etc-meisai.jp'],
    'dpoint': ['dpoint.jp', 'dpnt.jp', 'docomo.ne.jp', 'spmode.ne.jp'],
    'docomo': ['docomo.ne.jp', 'nttdocomo.co.jp', 'dpoint.jp', 'dpnt.jp', 'spmode.ne.jp'],
    'epos': ['eposcard.co.jp', 'mail.eposcard.co.jp', '01epos.jp'],
    'エポス': ['eposcard.co.jp', 'mail.eposcard.co.jp', '01epos.jp'],
    'ngrok': ['ngrok.com', 'm.ngrok.com'],
    'github': ['github.com', 'githubusercontent.com'],
    'gitlab': ['gitlab.com'],
    'bitbucket': ['bitbucket.org']
}

# スキャン状態を保持
scan_status = {
    'running': False,
    'result': None,
    'error': None
}

class EmailFraudFilter:
    def __init__(self, email_address, password, imap_server, imap_port=993):
        self.email_address = email_address
        self.password = password
        self.imap_server = imap_server
        self.imap_port = imap_port
        self.mail = None
        
    def connect(self):
        try:
            self.mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            self.mail.login(self.email_address, self.password)
            return True
        except Exception as e:
            raise Exception(f"接続エラー: {e}")
    
    def disconnect(self):
        if self.mail:
            try:
                self.mail.logout()
            except:
                pass
    
    def extract_domain(self, email_address):
        match = re.search(r'@([a-zA-Z0-9.-]+)', email_address)
        if match:
            return match.group(1).lower()
        return None
    
    def is_legitimate_domain(self, from_address, subject):
        sender_domain = self.extract_domain(from_address)
        if not sender_domain:
            return False, None, sender_domain
        
        subject_lower = subject.lower()
        from_lower = from_address.lower()
        
        for company, domains in LEGITIMATE_DOMAINS.items():
            for legitimate_domain in domains:
                if sender_domain.endswith(legitimate_domain):
                    bank_keywords = ['デビット', 'でびっと', '銀行', 'ぎんこう', '振込', '引き落とし', '口座']
                    has_company_keyword = company in subject_lower or company in from_lower
                    has_bank_keyword = any(keyword in subject or keyword in from_address for keyword in bank_keywords)
                    
                    if 'paypay' in sender_domain and (has_bank_keyword or 'visa' in subject_lower):
                        return True, 'paypay', sender_domain
                    
                    if has_company_keyword or (company == 'bank' and has_bank_keyword):
                        return True, company, sender_domain
        
        for company, domains in LEGITIMATE_DOMAINS.items():
            if company in subject_lower or company in from_lower:
                for legitimate_domain in domains:
                    if sender_domain.endswith(legitimate_domain):
                        return True, company, sender_domain
                return False, company, sender_domain
        
        return True, None, sender_domain
    
    def decode_mime_header(self, header):
        if header is None:
            return ""
        
        decoded_parts = decode_header(header)
        decoded_string = ""
        
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                try:
                    decoded_string += part.decode(encoding or 'utf-8', errors='ignore')
                except:
                    decoded_string += part.decode('utf-8', errors='ignore')
            else:
                decoded_string += str(part)
        
        return decoded_string
    
    def scan_inbox(self, folder='INBOX', max_emails=50):
        suspicious_emails = []
        
        try:
            self.mail.select(folder)
            status, messages = self.mail.search(None, 'ALL')
            
            if status != 'OK':
                return suspicious_emails
            
            email_ids = messages[0].split()
            email_ids = email_ids[-max_emails:] if len(email_ids) > max_emails else email_ids
            
            for email_id in email_ids:
                try:
                    status, msg_data = self.mail.fetch(email_id, '(RFC822)')
                    
                    if status != 'OK':
                        continue
                    
                    msg = email.message_from_bytes(msg_data[0][1])
                    subject = self.decode_mime_header(msg['Subject'])
                    from_address = self.decode_mime_header(msg['From'])
                    date = msg['Date']
                    
                    is_legitimate, company, sender_domain = self.is_legitimate_domain(
                        from_address, subject
                    )
                    
                    if not is_legitimate and company:
                        suspicious_emails.append({
                            'subject': subject,
                            'from': from_address,
                            'sender_domain': sender_domain,
                            'claimed_company': company,
                            'date': date
                        })
                
                except Exception as e:
                    continue
            
            return suspicious_emails
            
        except Exception as e:
            raise Exception(f"スキャンエラー: {e}")

def scan_emails():
    """バックグラウンドでメールをスキャン"""
    global scan_status
    
    scan_status['running'] = True
    scan_status['result'] = None
    scan_status['error'] = None
    
    try:
        email_accounts = []
        
        if GMAIL_ADDRESS and GMAIL_ADDRESS != "your-email@gmail.com":
            email_accounts.append({
                'address': GMAIL_ADDRESS,
                'password': GMAIL_PASSWORD,
                'server': 'imap.gmail.com',
                'type': 'Gmail'
            })
        
        if YAHOO_ADDRESS and YAHOO_ADDRESS != "your-email@yahoo.co.jp":
            email_accounts.append({
                'address': YAHOO_ADDRESS,
                'password': YAHOO_PASSWORD,
                'server': 'imap.mail.yahoo.co.jp',
                'type': 'Yahoo Mail'
            })
        
        if not email_accounts:
            raise Exception("環境変数が設定されていません")
        
        all_suspicious = []
        
        for account in email_accounts:
            filter_obj = EmailFraudFilter(
                account['address'],
                account['password'],
                account['server']
            )
            
            if filter_obj.connect():
                suspicious = filter_obj.scan_inbox(max_emails=MAX_EMAILS)
                for email_item in suspicious:
                    email_item['account'] = account['type']
                all_suspicious.extend(suspicious)
                filter_obj.disconnect()
        
        scan_status['result'] = {
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_suspicious': len(all_suspicious),
            'suspicious_emails': all_suspicious
        }
        
    except Exception as e:
        scan_status['error'] = str(e)
    
    finally:
        scan_status['running'] = False

# HTMLテンプレート（iPhone最適化）
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>メール詐欺検知</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 600px;
            margin: 0 auto;
        }
        
        .card {
            background: white;
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            margin-bottom: 20px;
        }
        
        h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
            text-align: center;
        }
        
        .subtitle {
            color: #666;
            text-align: center;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .scan-btn {
            width: 100%;
            padding: 18px;
            font-size: 18px;
            font-weight: bold;
            color: white;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 12px;
            cursor: pointer;
            transition: transform 0.2s;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        
        .scan-btn:active {
            transform: scale(0.98);
        }
        
        .scan-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        
        .loading.active {
            display: block;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .result {
            display: none;
        }
        
        .result.active {
            display: block;
        }
        
        .status {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-weight: bold;
            text-align: center;
        }
        
        .status.safe {
            background: #d4edda;
            color: #155724;
        }
        
        .status.warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .status.danger {
            background: #f8d7da;
            color: #721c24;
        }
        
        .email-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #dc3545;
        }
        
        .email-subject {
            font-weight: bold;
            color: #333;
            margin-bottom: 8px;
            font-size: 16px;
        }
        
        .email-from {
            color: #666;
            font-size: 14px;
            margin-bottom: 5px;
        }
        
        .email-domain {
            color: #dc3545;
            font-size: 13px;
            font-family: monospace;
        }
        
        .scan-time {
            text-align: center;
            color: #999;
            font-size: 12px;
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🛡️ メール詐欺検知</h1>
            <p class="subtitle">最新のメールをスキャンして詐欺メールを検知します</p>
            
            <button id="scanBtn" class="scan-btn" onclick="startScan()">
                📧 スキャン開始
            </button>
            
            <div id="loading" class="loading">
                <div class="spinner"></div>
                <p>スキャン中...</p>
            </div>
            
            <div id="result" class="result"></div>
        </div>
    </div>
    
    <script>
        function startScan() {
            const btn = document.getElementById('scanBtn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            
            btn.disabled = true;
            loading.classList.add('active');
            result.classList.remove('active');
            
            fetch('/api/scan', {method: 'POST'})
                .then(response => response.json())
                .then(data => {
                    checkStatus();
                })
                .catch(error => {
                    alert('エラーが発生しました: ' + error);
                    btn.disabled = false;
                    loading.classList.remove('active');
                });
        }
        
        function checkStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    if (data.running) {
                        setTimeout(checkStatus, 1000);
                    } else {
                        displayResult(data);
                    }
                });
        }
        
        function displayResult(data) {
            const btn = document.getElementById('scanBtn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            
            btn.disabled = false;
            loading.classList.remove('active');
            result.classList.add('active');
            
            if (data.error) {
                result.innerHTML = `
                    <div class="status danger">
                        ❌ エラーが発生しました<br>
                        ${data.error}
                    </div>
                `;
                return;
            }
            
            const count = data.result.total_suspicious;
            let html = '';
            
            if (count === 0) {
                html = '<div class="status safe">✅ 詐欺メールは検出されませんでした</div>';
            } else {
                html = `<div class="status danger">⚠️ ${count}件の詐欺メールを検出しました</div>`;
                
                data.result.suspicious_emails.forEach(email => {
                    html += `
                        <div class="email-item">
                            <div class="email-subject">${email.subject}</div>
                            <div class="email-from">📨 ${email.from}</div>
                            <div class="email-domain">🚨 ドメイン: ${email.sender_domain}</div>
                        </div>
                    `;
                });
            }
            
            html += `<div class="scan-time">スキャン完了: ${data.result.scan_date}</div>`;
            result.innerHTML = html;
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/scan', methods=['POST'])
def start_scan():
    if not scan_status['running']:
        thread = threading.Thread(target=scan_emails)
        thread.start()
        return jsonify({'status': 'started'})
    return jsonify({'status': 'already_running'})

@app.route('/api/status')
def get_status():
    return jsonify(scan_status)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)