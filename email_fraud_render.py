#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
メール詐欺検知プログラム - Render版（受信・表示のみ）
Acerから送信されたスキャン結果を受け取って表示
"""

from flask import Flask, render_template_string, jsonify, request
from datetime import datetime
import json
import os

app = Flask(__name__)

# スキャンリクエストフラグ
scan_request_flag = {
    'requested': False,
    'request_time': None
}

# 最新のスキャン結果を保持
latest_result = {
    'scan_date': None,
    'accounts': [],
    'total_suspicious': 0,
    'last_updated': None
}

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
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .refresh-btn {
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
            margin-bottom: 20px;
        }
        
        .refresh-btn:active {
            transform: scale(0.98);
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
        
        .account-section {
            margin-bottom: 25px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        
        .account-header {
            font-size: 18px;
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 2px solid #dee2e6;
        }
        
        .email-item {
            background: white;
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
        
        .auto-refresh {
            text-align: center;
            color: #666;
            font-size: 12px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🛡️ メール詐欺検知</h1>
            <p class="subtitle">Acerから最新のスキャン結果を表示</p>
            
            <button class="refresh-btn" onclick="location.reload()">
                🔄 更新
            </button>
            
            {% if acer_webhook_enabled %}
            <button class="refresh-btn" onclick="requestScan()" id="scanBtn" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                📧 今すぐスキャン
            </button>
            {% endif %}
            
            <div id="result">
                {% if data.scan_date %}
                    {% if data.total_suspicious == 0 %}
                        <div class="status safe">
                            ✅ 詐欺メールは検出されませんでした
                        </div>
                    {% else %}
                        <div class="status danger">
                            ⚠️ {{ data.total_suspicious }}件の詐欺メールを検出しました
                        </div>
                    {% endif %}
                    
                    {% for account in data.accounts %}
                        <div class="account-section">
                            <div class="account-header">
                                📧 {{ account.type }}
                            </div>
                            
                            {% if account.error %}
                                <p style="color: #dc3545;">❌ {{ account.error }}</p>
                            {% elif account.suspicious_count == 0 %}
                                <p style="color: #28a745;">✓ 詐欺メールなし</p>
                            {% else %}
                                {% for email in account.suspicious_emails %}
                                    <div class="email-item">
                                        <div class="email-subject">{{ email.subject }}</div>
                                        <div class="email-from">📨 {{ email.from }}</div>
                                        <div class="email-domain">🚨 ドメイン: {{ email.sender_domain }}</div>
                                    </div>
                                {% endfor %}
                            {% endif %}
                        </div>
                    {% endfor %}
                    
                    <div class="scan-time">
                        最終スキャン: {{ data.scan_date }}<br>
                        更新時刻: {{ data.last_updated }}
                    </div>
                {% else %}
                    <div class="status warning">
                        ⏳ まだスキャン結果がありません<br>
                        Acerからデータが送信されるまでお待ちください
                    </div>
                {% endif %}
            </div>
            
            <div class="auto-refresh">
                ※ページを更新すると最新の結果が表示されます
            </div>
        </div>
    </div>
    
    <script>
        function requestScan() {
            const btn = document.getElementById('scanBtn');
            if (btn) {
                btn.disabled = true;
                btn.textContent = '⏳ スキャン中...';
            }
            
            fetch('/api/request_scan', {method: 'POST'})
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    if (btn) {
                        btn.disabled = false;
                        btn.textContent = '📧 今すぐスキャン';
                    }
                    // 10秒後に自動更新
                    setTimeout(() => location.reload(), 10000);
                })
                .catch(error => {
                    alert('エラーが発生しました: ' + error);
                    if (btn) {
                        btn.disabled = false;
                        btn.textContent = '📧 今すぐスキャン';
                    }
                });
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, data=latest_result, acer_webhook_enabled=True)

@app.route('/api/request_scan', methods=['POST'])
def request_scan():
    """iPhoneからのスキャンリクエストを受付（フラグを立てる）"""
    global scan_request_flag
    
    try:
        scan_request_flag['requested'] = True
        scan_request_flag['request_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"✓ スキャンリクエストを受付: {scan_request_flag['request_time']}")
        
        return jsonify({
            'status': 'success',
            'message': 'スキャンリクエストを受け付けました。1分以内に実行されます。'
        }), 200
        
    except Exception as e:
        print(f"リクエスト受付エラー: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/check_flag', methods=['GET'])
def check_flag():
    """Acerからのフラグ確認（ポーリング用）"""
    global scan_request_flag
    
    if scan_request_flag['requested']:
        # フラグをクリア
        scan_request_flag['requested'] = False
        request_time = scan_request_flag['request_time']
        scan_request_flag['request_time'] = None
        
        print(f"✓ Acerにスキャン指示を送信")
        
        return jsonify({
            'scan_requested': True,
            'request_time': request_time
        }), 200
    else:
        return jsonify({
            'scan_requested': False
        }), 200

@app.route('/api/update', methods=['POST'])
def update_result():
    """Acerからスキャン結果を受信"""
    global latest_result
    
    try:
        data = request.get_json()
        
        if data and 'scan_date' in data:
            latest_result = data
            latest_result['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"✓ スキャン結果を受信: {data['total_suspicious']}件の詐欺メール")
            
            return jsonify({'status': 'success', 'message': '結果を更新しました'}), 200
        else:
            return jsonify({'status': 'error', 'message': '無効なデータ'}), 400
            
    except Exception as e:
        print(f"エラー: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/status')
def get_status():
    """現在の状態を取得"""
    return jsonify(latest_result)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
