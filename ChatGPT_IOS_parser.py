#!/usr/bin/env python3
"""
ChatGPT iPhone Backup Conversation Extractor
Digital Forensics Report Generator
"""

import json
import os
from datetime import datetime
from pathlib import Path
import sys

class ConversationExtractor:
    def __init__(self, conversations_dir):
        self.conversations_dir = Path(conversations_dir)
        self.conversations = []
        self.device_info = self.extract_device_info()
    
    def extract_device_info(self):
        """Extract device information from backup plists and segment files."""
        device_info = {
            'device_id': 'Unknown',
            'device_model': 'Unknown',
            'device_name': 'Unknown',
            'manufacturer': 'Unknown',
            'platform': 'Unknown',
            'os_version': 'Unknown',
            'os_build': 'Unknown',
            'screen_width': 'Unknown',
            'screen_height': 'Unknown',
            'app_version': 'Unknown',
            'app_build': 'Unknown',
            'app_bundle': 'Unknown',
            'timezone': 'Unknown',
            'locale': 'Unknown',
            'user_id': 'Unknown'
        }
        
        # Try to get device info from Segment analytics files (most comprehensive)
        try:
            import json
            segment_dir = self.conversations_dir.parent / 'segment' / 'oai'
            if segment_dir.exists():
                # Read the most recent segment file
                segment_files = sorted(segment_dir.glob('*-segment-events.temp'))
                if segment_files:
                    with open(segment_files[-1], 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Parse the JSON batch
                        if content.strip().startswith('{ "batch":'):
                            data = json.loads(content)
                            if 'batch' in data and len(data['batch']) > 0:
                                # Get the first event with context
                                for event in data['batch']:
                                    if 'context' in event:
                                        ctx = event['context']
                                        
                                        # Device info
                                        if 'device' in ctx:
                                            dev = ctx['device']
                                            device_info['device_model'] = dev.get('model', 'Unknown')
                                            device_info['device_name'] = dev.get('name', 'Unknown')
                                            device_info['manufacturer'] = dev.get('manufacturer', 'Unknown')
                                        
                                        # OS info
                                        if 'os' in ctx:
                                            os_data = ctx['os']
                                            device_info['platform'] = os_data.get('name', 'Unknown')
                                            device_info['os_version'] = os_data.get('version', 'Unknown')
                                        
                                        # Screen info
                                        if 'screen' in ctx:
                                            screen = ctx['screen']
                                            device_info['screen_width'] = str(screen.get('width', 'Unknown'))
                                            device_info['screen_height'] = str(screen.get('height', 'Unknown'))
                                        
                                        # App info
                                        if 'app' in ctx:
                                            app = ctx['app']
                                            device_info['app_version'] = app.get('version', 'Unknown')
                                            device_info['app_build'] = app.get('build', 'Unknown')
                                            device_info['app_bundle'] = app.get('namespace', 'Unknown')
                                        
                                        # Other info
                                        device_info['device_id'] = ctx.get('device_id', 'Unknown')
                                        device_info['timezone'] = ctx.get('timezone', 'Unknown')
                                        device_info['locale'] = ctx.get('locale', 'Unknown')
                                        
                                        # User ID
                                        if 'userId' in event:
                                            device_info['user_id'] = event['userId']
                                        
                                        # Get OS build from traits if available
                                        if 'traits' in event:
                                            traits = event['traits']
                                            if 'apple_os_version' in traits:
                                                device_info['os_build'] = traits.get('apple_os_version', 'Unknown')
                                        
                                        break
        except Exception as e:
            print(f"Note: Could not extract from segment files: {e}")
        
        # Fallback to plist if segment data not available
        if device_info['device_id'] == 'Unknown':
            try:
                import plistlib
                plist_path = self.conversations_dir.parent / 'Preferences' / 'com.openai.chat.plist'
                if plist_path.exists():
                    with open(plist_path, 'rb') as f:
                        data = plistlib.load(f)
                        if 'deviceIDBackup' in data:
                            device_info['device_id'] = data['deviceIDBackup']
                        device_info['app_bundle'] = 'com.openai.chat'
                        device_info['platform'] = 'iOS'
            except:
                pass
        
        return device_info
        
    def parse_tree_node(self, node_id, storage_dict, visited=None):
        """Recursively parse conversation tree nodes."""
        if visited is None:
            visited = set()
        
        if node_id in visited or node_id not in storage_dict:
            return []
        
        visited.add(node_id)
        node = storage_dict[node_id]
        
        messages = []
        
        # Extract message content
        if 'content' in node and 'content' in node['content']:
            content_data = node['content']['content']
            author = node['content'].get('author', {})
            role = author.get('role', 'unknown')
            
            # Get text parts
            parts = content_data.get('parts', [])
            text = ''
            images = []
            
            for part in parts:
                if isinstance(part, str):
                    text += part
                elif isinstance(part, dict):
                    if part.get('content_type') == 'text':
                        text += part.get('text', '')
                    elif part.get('content_type') == 'audio_transcription':
                        text += part.get('text', '')
                    elif part.get('content_type') == 'image_asset_pointer':
                        # Extract image metadata
                        img_data = {
                            'asset_pointer': part.get('asset_pointer', ''),
                            'width': part.get('width', 0),
                            'height': part.get('height', 0),
                            'size_bytes': part.get('size_bytes', 0),
                            'metadata': part.get('metadata', {})
                        }
                        images.append(img_data)
                        text += '[IMAGE_PLACEHOLDER]'
            
            if text and role in ['user', 'assistant', 'tool']:
                timestamp = node.get('created_at', 0)
                msg = {
                    'id': node_id,
                    'role': role,
                    'content': text.strip(),
                    'timestamp': timestamp,
                    'author_name': author.get('name', ''),
                    'create_time': node['content'].get('create_time', 0)
                }
                if images:
                    msg['images'] = images
                    # Get image title from metadata if available
                    node_metadata = node['content'].get('metadata', {})
                    if 'image_gen_title' in node_metadata:
                        msg['image_title'] = node_metadata['image_gen_title']
                messages.append(msg)
        
        # Process children
        children = node.get('children', [])
        for child_id in children:
            messages.extend(self.parse_tree_node(child_id, storage_dict, visited))
        
        return messages
    
    def extract_conversation(self, json_file):
        """Extract a single conversation from JSON file."""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Build storage dictionary for quick lookup
            storage_dict = {}
            if 'tree' in data and 'storage' in data['tree']:
                storage = data['tree']['storage']
                for i in range(0, len(storage), 2):
                    if i + 1 < len(storage):
                        node_id = storage[i]
                        node_data = storage[i + 1]
                        storage_dict[node_id] = node_data
            
            # Find root node
            root_id = data.get('tree', {}).get('current_node_id')
            if not root_id:
                return None
            
            # Parse the tree
            messages = self.parse_tree_node(root_id, storage_dict)
            
            # Sort messages by timestamp
            messages.sort(key=lambda x: x['timestamp'])
            
            # Filter out system messages and empty content
            messages = [m for m in messages if m['content'] and m['role'] in ['user', 'assistant', 'tool']]
            
            if not messages:
                return None
            
            return {
                'file': json_file.name,
                'title': data.get('title', 'Untitled Conversation'),
                'remote_id': data.get('remote_id', ''),
                'creation_date': data.get('creation_date', 0),
                'modification_date': data.get('modification_date', 0),
                'is_archived': data.get('is_archived', False),
                'model': data.get('configuration', {}).get('last_model', 'unknown'),
                'messages': messages,
                'message_count': len(messages),
                'user_message_count': len([m for m in messages if m['role'] == 'user']),
                'assistant_message_count': len([m for m in messages if m['role'] == 'assistant'])
            }
            
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
            return None
    
    def extract_all(self):
        """Extract all conversations from directory."""
        json_files = list(self.conversations_dir.glob('*.json'))
        
        for json_file in json_files:
            conv = self.extract_conversation(json_file)
            if conv:
                self.conversations.append(conv)
        
        # Sort by creation date
        self.conversations.sort(key=lambda x: x['creation_date'], reverse=True)
        
        return self.conversations
    
    def format_timestamp(self, cocoa_timestamp):
        """Convert Cocoa timestamp to readable format."""
        if cocoa_timestamp == 0:
            return "Unknown"
        
        # Cocoa timestamps are seconds since Jan 1, 2001
        cocoa_epoch = datetime(2001, 1, 1)
        dt = cocoa_epoch.timestamp() + cocoa_timestamp
        return datetime.fromtimestamp(dt).strftime('%Y-%m-%d %H:%M:%S')
    
    def generate_html_report(self, output_file):
        """Generate HTML forensic report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ChatGPT Conversation Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: #161b22;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            overflow: hidden;
            border: 1px solid #30363d;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
            color: #e6edf3;
            padding: 40px;
            text-align: center;
            border-bottom: 2px solid #4b5563;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .report-meta {{
            background: #1c2128;
            padding: 30px 40px;
            border-bottom: 2px solid #30363d;
        }}
        
        .report-meta h2 {{
            color: #e6edf3;
        }}
        
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .meta-item {{
            background: #21262d;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #6b7280;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            border: 1px solid #30363d;
        }}
        
        .meta-item .label {{
            font-weight: 600;
            color: #8b949e;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .meta-item .value {{
            font-size: 1.8em;
            color: #e6edf3;
            font-weight: bold;
            margin-top: 5px;
        }}
        
        .content {{
            padding: 40px;
            background: #161b22;
        }}
        
        .content h2 {{
            color: #e6edf3;
        }}
        
        .conversation {{
            background: #1c2128;
            margin-bottom: 30px;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            border: 1px solid #30363d;
        }}
        
        .conversation-header {{
            background: linear-gradient(135deg, #374151 0%, #4b5563 100%);
            color: #e6edf3;
            padding: 25px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
        }}
        
        .conversation-header:hover {{
            background: linear-gradient(135deg, #4b5563 0%, #6b7280 100%);
        }}
        
        .conversation-title {{
            font-size: 1.4em;
            font-weight: 600;
        }}
        
        .conversation-stats {{
            display: flex;
            gap: 20px;
            font-size: 0.9em;
            opacity: 0.95;
        }}
        
        .conversation-meta {{
            background: #21262d;
            padding: 20px 25px;
            border-bottom: 1px solid #30363d;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        
        .meta-field {{
            font-size: 0.9em;
            color: #8b949e;
        }}
        
        .meta-field strong {{
            color: #c9d1d9;
        }}
        
        .messages {{
            padding: 25px;
            max-height: 600px;
            overflow-y: auto;
            background: #0d1117;
        }}
        
        .message {{
            margin-bottom: 20px;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid;
            animation: fadeIn 0.3s ease;
            border: 1px solid #30363d;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .message.user {{
            background: #1c2d3a;
            border-left-color: #4b8ec8;
        }}
        
        .message.assistant {{
            background: #1a2b2e;
            border-left-color: #5f8575;
        }}
        
        .message.tool {{
            background: #2b2416;
            border-left-color: #8b7355;
        }}
        
        .message-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 0.9em;
        }}
        
        .message-role {{
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .message.user .message-role {{
            color: #6ba9e5;
        }}
        
        .message.assistant .message-role {{
            color: #7fb89a;
        }}
        
        .message.tool .message-role {{
            color: #b8986f;
        }}
        
        .message-time {{
            color: #8b949e;
        }}
        
        .message-content {{
            color: #c9d1d9;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .toggle-icon {{
            transition: transform 0.3s ease;
        }}
        
        .collapsed .toggle-icon {{
            transform: rotate(-90deg);
        }}
        
        .collapsed .messages {{
            display: none;
        }}
        
        .footer {{
            background: #0d1117;
            color: #8b949e;
            padding: 30px;
            text-align: center;
            border-top: 2px solid #30363d;
        }}
        
        .timestamp-note {{
            background: #2d2a1f;
            border: 1px solid #6b5d3f;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            color: #c9a86a;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        table th {{
            background: #21262d;
            color: #8b949e;
            text-align: left;
            padding: 12px;
            font-weight: 600;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border: 1px solid #30363d;
        }}
        
        table td {{
            background: #1c2128;
            color: #c9d1d9;
            padding: 12px;
            border: 1px solid #30363d;
        }}
        
        table tr:hover td {{
            background: #21262d;
        }}
        
        .search-container {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
        }}
        
        .search-input {{
            width: 100%;
            background: #0d1117;
            border: 2px solid #30363d;
            border-radius: 6px;
            padding: 12px 15px;
            color: #c9d1d9;
            font-size: 16px;
            outline: none;
            transition: border-color 0.3s;
        }}
        
        .search-input:focus {{
            border-color: #58a6ff;
        }}
        
        .search-input::placeholder {{
            color: #8b949e;
        }}
        
        .search-stats {{
            margin-top: 10px;
            color: #8b949e;
            font-size: 0.9em;
        }}
        
        .highlight {{
            background: #6e7681;
            color: #ffffff;
            font-weight: bold;
            border-radius: 2px;
            padding: 2px 4px;
        }}
        
        .message.hidden {{
            display: none;
        }}
        
        ::-webkit-scrollbar {{
            width: 10px;
            height: 10px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: #161b22;
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: #30363d;
            border-radius: 5px;
        }}
        
        ::-webkit-scrollbar-thumb:hover {{
            background: #484f58;
        }}
                
        @media print {{
            body {{
                background: white;
            }}
            
            .conversation {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ChatGPT Conversation Report</h1>
        </div>
        
        <div class="report-meta">
            <h2>Report Summary</h2>
            <table>
                <tr>
                    <th>Report Generated</th>
                    <td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <th>Total Conversations</th>
                    <td>{len(self.conversations)}</td>
                </tr>
                <tr>
                    <th>Total Messages</th>
                    <td>{sum(c['message_count'] for c in self.conversations)}</td>
                    <th>User Prompts</th>
                    <td>{sum(c['user_message_count'] for c in self.conversations)}</td>
                </tr>
            </table>
            
            <h2 style="margin-top: 30px;">Device Information</h2>
            <table>
                <tr>
                    <th>Device Model</th>
                    <td>{self.device_info['device_name']} ({self.device_info['device_model']})</td>
                    <th>Manufacturer</th>
                    <td>{self.device_info['manufacturer']}</td>
                </tr>
                <tr>
                    <th>Operating System</th>
                    <td>{self.device_info['platform']} {self.device_info['os_version']}</td>
                    <th>Application</th>
                    <td>{self.device_info['app_bundle']}</td>
                </tr>
                <tr>
                    <th>App Version</th>
                    <td>{self.device_info['app_version']} (Build {self.device_info['app_build']})</td>
                    <th>Screen Resolution</th>
                    <td>{self.device_info['screen_width']} x {self.device_info['screen_height']}</td>
                </tr>
                <tr>
                    <th>Locale / Timezone</th>
                    <td>{self.device_info['locale']} / {self.device_info['timezone']}</td>
                    <th></th>
                    <td></td>
                </tr>
                <tr>
                    <th>User ID</th>
                    <td colspan="3" style="word-break: break-all;">{self.device_info['user_id']}</td>
                </tr>
                <tr>
                    <th>Device ID</th>
                    <td colspan="3" style="word-break: break-all;">{self.device_info['device_id']}</td>
                </tr>
            </table>
            
            <div class="timestamp-note">
                <strong>Note:</strong> Timestamps are converted from Apple Cocoa format (seconds since January 1, 2001).
            </div>
        </div>
        
        <div class="content">
            <h2 style="margin-bottom: 30px;">Conversation Details</h2>
            
            <div class="search-container">
                <input type="text" 
                       class="search-input" 
                       id="searchInput" 
                       placeholder="Search messages... (press Enter or type to filter)"
                       onkeyup="searchMessages()">
                <div class="search-stats" id="searchStats"></div>
            </div>
"""
        
        for idx, conv in enumerate(self.conversations, 1):
            creation = self.format_timestamp(conv['creation_date'])
            modification = self.format_timestamp(conv['modification_date'])
            
            html += f"""
            <div class="conversation" id="conv-{idx}">
                <div class="conversation-header" onclick="toggleConversation({idx})">
                    <div>
                        <div class="conversation-title">{conv['title']}</div>
                    </div>
                    <div class="conversation-stats">
                        <span>{conv['message_count']} messages</span>
                        <span>{conv['user_message_count']} prompts</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                </div>
                
                <div class="conversation-meta">
                    <div class="meta-field">
                        <strong>File:</strong> {conv['file']}
                    </div>
                    <div class="meta-field">
                        <strong>Created:</strong> {creation}
                    </div>
                    <div class="meta-field">
                        <strong>Modified:</strong> {modification}
                    </div>
                    <div class="meta-field">
                        <strong>Model:</strong> {conv['model']}
                    </div>
                    <div class="meta-field">
                        <strong>Remote ID:</strong> {conv['remote_id'][:20]}...
                    </div>
                    <div class="meta-field">
                        <strong>Archived:</strong> {'Yes' if conv['is_archived'] else 'No'}
                    </div>
                </div>
                
                <div class="messages">
"""
            
            for msg in conv['messages']:
                role = msg['role']
                timestamp = self.format_timestamp(msg['timestamp'])
                content = msg['content']
                
                # Handle images
                if 'images' in msg:
                    for img in msg['images']:
                        img_info = f"\n\n[IMAGE REFERENCE - Stored in Cloud]\n"
                        if 'image_title' in msg:
                            img_info += f"Title: {msg['image_title']}\n"
                        img_info += f"Asset: {img['asset_pointer']}\n"
                        img_info += f"Dimensions: {img['width']}x{img['height']}\n"
                        img_info += f"Size: {img['size_bytes']:,} bytes ({img['size_bytes']/1024/1024:.2f} MB)\n"
                        if 'dalle' in img['metadata']:
                            dalle_meta = img['metadata']['dalle']
                            if 'gen_id' in dalle_meta:
                                img_info += f"Generation ID: {dalle_meta['gen_id']}\n"
                        img_info += f"Note: Image is stored remotely on OpenAI servers (sediment:// protocol)\n"
                        content = content.replace('[IMAGE_PLACEHOLDER]', img_info)
                
                # Truncate very long messages for display
                if len(content) > 5000:
                    content = content[:5000] + "\n\n[... content truncated for display ...]"
                
                html += f"""
                    <div class="message {role}">
                        <div class="message-header">
                            <span class="message-role">{role}</span>
                            <span class="message-time">{timestamp}</span>
                        </div>
                        <div class="message-content">{self.escape_html(content)}</div>
                    </div>
"""
            
            html += """
                </div>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p><strong>ChatGPT Conversation Report</strong></p>
            <p style="margin-top: 10px; opacity: 0.8; font-size: 0.9em;">
                This report contains extracted conversation data from ChatGPT mobile application backup files.<br>
                For forensic and investigative purposes only. Handle according to data protection regulations.
            </p>
            <div style="margin-top: 25px; padding-top: 20px; border-top: 1px solid #30363d;">
                <p><strong>North Loop Consulting</strong></p>
                <p style="margin-top: 5px; font-size: 0.85em;">Copyright © 2026 North Loop Consulting. All rights reserved.</p>
            </div>
        </div>
    </div>
    
    <script>
        function toggleConversation(id) {
            const conv = document.getElementById('conv-' + id);
            conv.classList.toggle('collapsed');
        }
        
        function highlightText(text, searchTerm) {
            if (!searchTerm) return text;
            const lowerText = text.toLowerCase();
            const lowerSearch = searchTerm.toLowerCase();
            let result = '';
            let lastIndex = 0;
            let index = lowerText.indexOf(lowerSearch);
            
            while (index !== -1) {
                result += text.substring(lastIndex, index);
                result += '<span class="highlight">' + text.substring(index, index + searchTerm.length) + '</span>';
                lastIndex = index + searchTerm.length;
                index = lowerText.indexOf(lowerSearch, lastIndex);
            }
            result += text.substring(lastIndex);
            return result;
        }
        
        function searchMessages() {
            console.log('searchMessages called');
            const searchInput = document.getElementById('searchInput');
            const searchTerm = searchInput.value.toLowerCase();
            console.log('Search term:', searchTerm);
            const messages = document.querySelectorAll('.message');
            const conversations = document.querySelectorAll('.conversation');
            console.log('Found', messages.length, 'messages and', conversations.length, 'conversations');
            let matchCount = 0;
            let hiddenConvCount = 0;
            
            // Clear previous highlights
            if (searchTerm === '') {
                messages.forEach(msg => {
                    const content = msg.querySelector('.message-content');
                    const original = content.getAttribute('data-original');
                    if (original) {
                        content.innerHTML = original;
                    }
                    msg.classList.remove('hidden');
                });
                conversations.forEach(conv => {
                    conv.style.display = 'block';
                    conv.classList.remove('collapsed');
                });
                document.getElementById('searchStats').textContent = '';
                return;
            }
            
            // Search and highlight
            conversations.forEach(conv => {
                let convHasMatch = false;
                const convMessages = conv.querySelectorAll('.message');
                console.log('Checking conversation with', convMessages.length, 'messages');
                
                convMessages.forEach(msg => {
                    const content = msg.querySelector('.message-content');
                    const role = msg.querySelector('.message-role');
                    const text = content.textContent.toLowerCase();
                    const roleText = role.textContent.toLowerCase();
                    
                    if (text.includes(searchTerm) || roleText.includes(searchTerm)) {
                        msg.classList.remove('hidden');
                        convHasMatch = true;
                        matchCount++;
                        
                        // Highlight matching text
                        if (!content.getAttribute('data-original')) {
                            content.setAttribute('data-original', content.innerHTML);
                        }
                        const original = content.getAttribute('data-original');
                        const highlighted = highlightText(original, searchTerm);
                        content.innerHTML = highlighted;
                    } else {
                        msg.classList.add('hidden');
                    }
                });
                
                // Show/hide entire conversation based on matches
                if (convHasMatch) {
                    conv.style.display = 'block';
                    conv.classList.remove('collapsed');
                } else {
                    conv.style.display = 'none';
                    hiddenConvCount++;
                }
            });
            
            // Update stats
            const totalConvs = conversations.length;
            const visibleConvs = totalConvs - hiddenConvCount;
            console.log('Match count:', matchCount, 'Visible convs:', visibleConvs);
            document.getElementById('searchStats').textContent = 
                'Found ' + matchCount + ' message' + (matchCount !== 1 ? 's' : '') + ' in ' + visibleConvs + ' conversation' + (visibleConvs !== 1 ? 's' : '');
        }
        
        // Optional: Add keyboard navigation
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                // Clear search
                const searchInput = document.getElementById('searchInput');
                if (searchInput.value !== '') {
                    searchInput.value = '';
                    searchMessages();
                } else {
                    // Collapse all conversations
                    document.querySelectorAll('.conversation').forEach(conv => {
                        conv.classList.add('collapsed');
                    });
                }
            }
        });
    </script>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"\nReport generated: {output_file}")
        print(f"Processed {len(self.conversations)} conversations")
        print(f"Total messages: {sum(c['message_count'] for c in self.conversations)}")
        
    def escape_html(self, text):
        """Escape HTML special characters."""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))

def main():
    # Get the directory containing this script
    script_dir = Path(__file__).parent
    app_support_dir = script_dir / "Library" / "Application Support"
    
    # Find conversations directory (supports any GUID)
    conversations_dir = None
    if app_support_dir.exists():
        # Look for conversations-v3-* folders
        conv_dirs = list(app_support_dir.glob('conversations-v3-*'))
        if conv_dirs:
            # Prefer folders with content, and non-default folders
            conv_dirs_with_content = []
            for d in conv_dirs:
                json_files = list(d.glob('*.json'))
                if json_files:
                    # Prioritize non-default folders with content
                    priority = 0 if 'default' not in d.name.lower() else 1
                    conv_dirs_with_content.append((priority, len(json_files), d))
            
            if conv_dirs_with_content:
                # Sort by priority (non-default first), then by number of files (most first)
                conv_dirs_with_content.sort(key=lambda x: (x[0], -x[1]))
                conversations_dir = conv_dirs_with_content[0][2]
                if len(conv_dirs) > 1:
                    print(f"Note: Found {len(conv_dirs)} conversation folders, using: {conversations_dir.name}")
            elif conv_dirs:
                conversations_dir = conv_dirs[0]
    
    if not conversations_dir or not conversations_dir.exists():
        print(f"Error: No conversations directory found in {app_support_dir}")
        print(f"Looking for folders matching pattern: conversations-v3-*")
        sys.exit(1)
    
    print("ChatGPT Conversation Forensic Extractor")
    print("=" * 60)
    print(f"Source: {conversations_dir}")
    print("\nExtracting conversations...")
    
    extractor = ConversationExtractor(conversations_dir)
    extractor.extract_all()
    
    output_file = script_dir / "chatgpt_forensic_report.html"
    extractor.generate_html_report(output_file)
    
    print(f"\nDone! Open the report in your browser:")
    print(f"   file://{output_file.absolute()}")

if __name__ == "__main__":
    main()
