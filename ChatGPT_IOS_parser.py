#!/usr/bin/env python3
"""
ChatGPT iPhone Backup Conversation Extractor - Forensic Edition
Digital Forensics Report Generator with Chain of Custody

VERSION: 2.0 
Tested on: ChatGPT iOS versions 1.2024.080 (Build 24781), 1.2025.350 (Build 20387701780)

Author: North Loop Consulting
License: Forensic Use Only
"""

import json
import os
import hashlib
import csv
import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
import logging

class ForensicLogger:
    """Handles audit logging for forensic documentation."""
    
    def __init__(self, log_file):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('ForensicExtractor')
    
    def info(self, message):
        self.logger.info(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def critical(self, message):
        self.logger.critical(message)

class FileHasher:
    """Generates and verifies cryptographic hashes for evidence integrity."""
    
    @staticmethod
    def md5_file(file_path):
        """Calculate MD5 hash of a file."""
        md5 = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    md5.update(chunk)
            return md5.hexdigest()
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    @staticmethod
    def md5_string(text):
        """Calculate MD5 hash of a string."""
        return hashlib.md5(text.encode('utf-8')).hexdigest()

class ConversationExtractor:
    def __init__(self, conversations_dir, logger=None, case_info=None):
        self.conversations_dir = Path(conversations_dir)
        self.conversations = []
        self.logger = logger
        self.case_info = case_info or {}
        self.file_hashes = {}
        self.extraction_stats = {
            'total_files': 0,
            'processed_files': 0,
            'failed_files': 0,
            'total_conversations': 0,
            'total_messages': 0,
            'errors': []
        }
        
        if self.logger:
            self.logger.info(f"Initialized extractor for: {conversations_dir}")
        
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
        
        # Try to get device info from Segment analytics files
        try:
            segment_dir = None
            possible_paths = [
                self.conversations_dir.parent / 'segment' / 'oai',
                self.conversations_dir.parent.parent.parent / 'Documents' / 'segment' / 'oai',
            ]
            for path in possible_paths:
                if path.exists():
                    segment_dir = path
                    if self.logger:
                        self.logger.info(f"Found segment directory: {path}")
                    break
            
            if segment_dir:
                segment_files = sorted(segment_dir.glob('*-segment-events*'))
                if segment_files:
                    segment_file = segment_files[-1]
                    if self.logger:
                        self.logger.info(f"Reading segment file: {segment_file}")
                    
                    with open(segment_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        data = None
                        if content.strip().startswith('{ "batch":') or content.strip().startswith('{"batch":'):
                            data = json.loads(content)
                        
                        if data and 'batch' in data and len(data['batch']) > 0:
                            for event in data['batch']:
                                if 'context' in event:
                                    ctx = event['context']
                                    
                                    if 'device' in ctx:
                                        dev = ctx['device']
                                        device_info['device_model'] = dev.get('model', 'Unknown')
                                        device_info['device_name'] = dev.get('name', 'Unknown')
                                        device_info['manufacturer'] = dev.get('manufacturer', 'Unknown')
                                    
                                    if 'os' in ctx:
                                        os_data = ctx['os']
                                        device_info['platform'] = os_data.get('name', 'Unknown')
                                        device_info['os_version'] = os_data.get('version', 'Unknown')
                                    
                                    if 'screen' in ctx:
                                        screen = ctx['screen']
                                        device_info['screen_width'] = str(screen.get('width', 'Unknown'))
                                        device_info['screen_height'] = str(screen.get('height', 'Unknown'))
                                    
                                    if 'app' in ctx:
                                        app = ctx['app']
                                        device_info['app_version'] = app.get('version', 'Unknown')
                                        device_info['app_build'] = app.get('build', 'Unknown')
                                        device_info['app_bundle'] = app.get('namespace', 'Unknown')
                                    
                                    device_info['timezone'] = ctx.get('timezone', 'Unknown')
                                    device_info['locale'] = ctx.get('locale', 'Unknown')
                                    
                                    if 'device_id' in ctx:
                                        device_info['device_id'] = ctx['device_id']
                                    elif 'device' in ctx and 'id' in ctx['device']:
                                        device_info['device_id'] = ctx['device']['id']
                                    
                                    if 'userId' in event:
                                        device_info['user_id'] = event['userId']
                                    
                                    if 'traits' in event:
                                        traits = event['traits']
                                        if 'apple_os_version' in traits:
                                            device_info['os_build'] = traits.get('apple_os_version', 'Unknown')
                                        if 'device_id' in traits and device_info['device_id'] == 'Unknown':
                                            device_info['device_id'] = traits['device_id']
                                    
                                    break
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Could not extract from segment files: {e}")
        
        # Fallback to plist
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
                    if self.logger:
                        self.logger.info("Extracted device info from plist file")
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Could not read plist: {e}")
        
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
        
        if 'content' in node and 'content' in node['content']:
            content_data = node['content']['content']
            author = node['content'].get('author', {})
            role = author.get('role', 'unknown')
            
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
                    node_metadata = node['content'].get('metadata', {})
                    if 'image_gen_title' in node_metadata:
                        msg['image_title'] = node_metadata['image_gen_title']
                messages.append(msg)
        
        children = node.get('children', [])
        for child_id in children:
            messages.extend(self.parse_tree_node(child_id, storage_dict, visited))
        
        return messages
    
    def extract_conversation(self, json_file, compute_hash=True):
        """Extract a single conversation from JSON file."""
        try:
            self.extraction_stats['processed_files'] += 1
            
            # Compute hash if requested
            if compute_hash:
                file_hash = FileHasher.md5_file(json_file)
                self.file_hashes[str(json_file)] = file_hash
                if self.logger:
                    self.logger.info(f"Hash: {json_file.name} = {file_hash}")
            
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            storage_dict = {}
            if 'tree' in data and 'storage' in data['tree']:
                storage = data['tree']['storage']
                if isinstance(storage, dict):
                    storage_dict = storage
                elif isinstance(storage, list):
                    for i in range(0, len(storage), 2):
                        if i + 1 < len(storage):
                            node_id = storage[i]
                            node_data = storage[i + 1]
                            storage_dict[node_id] = node_data
            
            root_id = data.get('tree', {}).get('root_node_id')
            if not root_id:
                root_id = data.get('tree', {}).get('current_node_id')
            if not root_id:
                root_id = data.get('current_leaf_node_id')
            if not root_id:
                return None
            
            messages = self.parse_tree_node(root_id, storage_dict)
            messages.sort(key=lambda x: x['timestamp'])
            messages = [m for m in messages if m['content'] and m['role'] in ['user', 'assistant', 'tool']]
            
            if not messages:
                return None
            
            self.extraction_stats['total_messages'] += len(messages)
            
            return {
                'file': json_file.name,
                'file_path': str(json_file),
                'file_hash': self.file_hashes.get(str(json_file), 'Not computed'),
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
            self.extraction_stats['failed_files'] += 1
            error_msg = f"Error processing {json_file}: {e}"
            self.extraction_stats['errors'].append(error_msg)
            if self.logger:
                self.logger.error(error_msg)
            return None
    
    def extract_all(self, date_from=None, date_to=None, compute_hashes=True):
        """Extract all conversations from directory with optional date filtering."""
        json_files = list(self.conversations_dir.glob('*.json'))
        self.extraction_stats['total_files'] = len(json_files)
        
        if self.logger:
            self.logger.info(f"Found {len(json_files)} conversation files")
        
        for json_file in json_files:
            conv = self.extract_conversation(json_file, compute_hash=compute_hashes)
            if conv:
                # Apply date filtering if specified
                if date_from or date_to:
                    conv_date = self.cocoa_to_datetime(conv['creation_date'])
                    if date_from and conv_date < date_from:
                        continue
                    if date_to and conv_date > date_to:
                        continue
                
                self.conversations.append(conv)
        
        self.conversations.sort(key=lambda x: x['creation_date'], reverse=True)
        self.extraction_stats['total_conversations'] = len(self.conversations)
        
        if self.logger:
            self.logger.info(f"Successfully extracted {len(self.conversations)} conversations")
        
        return self.conversations
    
    def cocoa_to_datetime(self, cocoa_timestamp):
        """Convert Cocoa timestamp to datetime object."""
        if cocoa_timestamp == 0:
            return datetime(2001, 1, 1)
        cocoa_epoch = datetime(2001, 1, 1)
        dt = cocoa_epoch.timestamp() + cocoa_timestamp
        return datetime.fromtimestamp(dt)
    
    def format_timestamp(self, cocoa_timestamp):
        """Convert Cocoa timestamp to readable format."""
        if cocoa_timestamp == 0:
            return "Unknown"
        return self.cocoa_to_datetime(cocoa_timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
    def export_to_json(self, output_file):
        """Export conversations to JSON format."""
        data = {
            'case_info': self.case_info,
            'device_info': self.device_info,
            'extraction_stats': self.extraction_stats,
            'extraction_timestamp': datetime.now(timezone.utc).isoformat(),
            'file_hashes': self.file_hashes,
            'conversations': self.conversations
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        if self.logger:
            self.logger.info(f"Exported to JSON: {output_file}")
    
    def export_to_csv(self, output_file):
        """Export conversations to CSV format (flattened messages)."""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Case Number', 'Evidence ID', 'Conversation Title', 'Conversation ID',
                'Conversation Created', 'Message ID', 'Message Timestamp', 'Role',
                'Content', 'Model', 'File Hash'
            ])
            
            for conv in self.conversations:
                for msg in conv['messages']:
                    writer.writerow([
                        self.case_info.get('case_number', 'N/A'),
                        self.case_info.get('evidence_id', 'N/A'),
                        conv['title'],
                        conv['remote_id'],
                        self.format_timestamp(conv['creation_date']),
                        msg['id'],
                        self.format_timestamp(msg['timestamp']),
                        msg['role'],
                        msg['content'][:1000],  # Truncate for CSV
                        conv['model'],
                        conv['file_hash']
                    ])
        
        if self.logger:
            self.logger.info(f"Exported to CSV: {output_file}")
    
    def generate_html_report(self, output_file):
        """Generate HTML forensic report."""
        case_section = ""
        if self.case_info:
            case_section = f"""
            <h2>Case Information</h2>
            <table>
                <tr>
                    <th>Case Number</th>
                    <td>{self.case_info.get('case_number', 'N/A')}</td>
                    <th>Evidence ID</th>
                    <td>{self.case_info.get('evidence_id', 'N/A')}</td>
                    <th>Examiner</th>
                    <td>{self.case_info.get('examiner', 'N/A')}</td>
                    <th>Examination Date</th>
                    <td>{self.case_info.get('exam_date', 'N/A')}</td>
                </tr>
            </table>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ChatGPT Forensic Analysis Report - Case {self.case_info.get('case_number', 'N/A')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0d1117; padding: 20px; line-height: 1.6; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: #161b22; border-radius: 15px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); overflow: hidden; border: 1px solid #30363d; }}
        .header {{ background: linear-gradient(135deg, #1f2937 0%, #374151 100%); color: #e6edf3; padding: 30px; text-align: center; border-bottom: 2px solid #4b5563; }}
        .header h1 {{ font-size: 2.2em; margin-bottom: 5px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }}
        .report-meta {{ background: #1c2128; padding: 30px 40px; border-bottom: 2px solid #30363d; }}
        .report-meta h2 {{ color: #e6edf3; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        table th {{ background: #21262d; color: #8b949e; text-align: left; padding: 12px; font-weight: 600; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.5px; border: 1px solid #30363d; }}
        table td {{ background: #1c2128; color: #c9d1d9; padding: 12px; border: 1px solid #30363d; word-break: break-word; }}
        table tr:hover td {{ background: #21262d; }}
        .content {{ padding: 40px; background: #161b22; }}
        .content h2 {{ color: #e6edf3; margin-bottom: 20px; }}
        .conversation {{ background: #1c2128; margin-bottom: 30px; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.3); border: 1px solid #30363d; }}
        .conversation-header {{ background: linear-gradient(135deg, #374151 0%, #4b5563 100%); color: #e6edf3; padding: 25px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; transition: all 0.3s ease; }}
        .conversation-header:hover {{ background: linear-gradient(135deg, #4b5563 0%, #6b7280 100%); }}
        .conversation-title {{ font-size: 1.4em; font-weight: 600; }}
        .conversation-stats {{ display: flex; gap: 20px; font-size: 0.9em; opacity: 0.95; }}
        .conversation-meta {{ background: #21262d; padding: 20px 25px; border-bottom: 1px solid #30363d; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .meta-field {{ font-size: 0.9em; color: #8b949e; }}
        .meta-field strong {{ color: #c9d1d9; }}
        .messages {{ padding: 25px; max-height: 600px; overflow-y: auto; background: #0d1117; }}
        .message {{ margin-bottom: 20px; padding: 20px; border-radius: 10px; border-left: 4px solid; border: 1px solid #30363d; }}
        .message.user {{ background: #1c2d3a; border-left-color: #4b8ec8; }}
        .message.assistant {{ background: #1a2b2e; border-left-color: #5f8575; }}
        .message.tool {{ background: #2b2416; border-left-color: #8b7355; }}
        .message-header {{ display: flex; justify-content: space-between; margin-bottom: 10px; font-size: 0.9em; }}
        .message-role {{ font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }}
        .message.user .message-role {{ color: #6ba9e5; }}
        .message.assistant .message-role {{ color: #7fb89a; }}
        .message.tool .message-role {{ color: #b8986f; }}
        .message-time {{ color: #8b949e; }}
        .message-content {{ color: #c9d1d9; white-space: pre-wrap; word-wrap: break-word; }}
        .toggle-icon {{ transition: transform 0.3s ease; }}
        .collapsed .toggle-icon {{ transform: rotate(-90deg); }}
        .collapsed .messages {{ display: none; }}
        .footer {{ background: #0d1117; color: #8b949e; padding: 30px; text-align: center; border-top: 2px solid #30363d; }}
        .hash-section {{ background: #2d2a1f; border: 1px solid #6b5d3f; border-radius: 8px; padding: 15px; margin: 20px 0; color: #c9a86a; font-family: monospace; font-size: 0.85em; }}
        .timestamp-note {{ background: #2d2a1f; border: 1px solid #6b5d3f; border-radius: 8px; padding: 15px; margin: 20px 0; color: #c9a86a; }}
        .search-container {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 20px 0; position: sticky; top: 0; z-index: 100; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3); }}
        .search-input {{ width: 100%; background: #0d1117; border: 2px solid #30363d; border-radius: 6px; padding: 12px 15px; color: #c9d1d9; font-size: 16px; outline: none; transition: border-color 0.3s; }}
        .search-input:focus {{ border-color: #58a6ff; }}
        .search-stats {{ margin-top: 10px; color: #8b949e; font-size: 0.9em; }}
        .highlight {{ background: #6e7681; color: #ffffff; font-weight: bold; border-radius: 2px; padding: 2px 4px; }}
        .message.hidden {{ display: none; }}
        ::-webkit-scrollbar {{ width: 10px; height: 10px; }}
        ::-webkit-scrollbar-track {{ background: #161b22; }}
        ::-webkit-scrollbar-thumb {{ background: #30363d; border-radius: 5px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #484f58; }}
        @media print {{ body {{ background: white; }} .conversation {{ page-break-inside: avoid; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ChatGPT Forensic Analysis Report</h1>
        </div>
        
        <div class="report-meta">
            {case_section}
            
            <h2>Extraction Summary</h2>
            <table>
                <tr>
                    <th>Report Generated</th>
                    <td>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
                    <th>Conversations</th>
                    <td>{len(self.conversations)}</td>
                    <th>Messages</th>
                    <td>{sum(c['message_count'] for c in self.conversations)}</td>
                    <th>Files Processed</th>
                    <td>{self.extraction_stats['processed_files']}</td>
                </tr>
            </table>
            
            <h2>Device Information</h2>
            <table>
                <tr>
                    <th>Device Model</th>
                    <td>{self.device_info['device_name']} ({self.device_info['device_model']})</td>
                    <th>Manufacturer</th>
                    <td>{self.device_info['manufacturer']}</td>
                    <th>Operating System</th>
                    <td>{self.device_info['platform']} {self.device_info['os_version']}</td>
                </tr>
                <tr>
                    <th>Application</th>
                    <td>{self.device_info['app_bundle']}</td>
                    <th>App Version</th>
                    <td>{self.device_info['app_version']} (Build {self.device_info['app_build']})</td>
                    <th>Screen Resolution</th>
                    <td>{self.device_info['screen_width']} x {self.device_info['screen_height']}</td>
                </tr>
                <tr>
                    <th>Locale</th>
                    <td colspan="2">{self.device_info['locale']}</td>
                    <th>Timezone</th>
                    <td colspan="2">{self.device_info['timezone']}</td>
                </tr>
                <tr>
                    <th>User ID</th>
                    <td colspan="2" style="word-break: break-all;">{self.device_info['user_id']}</td>
                    <th>Device ID</th>
                    <td colspan="2" style="word-break: break-all;">{self.device_info['device_id']}</td>
                </tr>
            </table>
            
            <div class="timestamp-note">
                <strong>Note:</strong> Timestamps are converted from Apple Cocoa format (seconds since January 1, 2001). File hashes are MD5.
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
                        <div class="conversation-title">{self.escape_html(conv['title'])}</div>
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
                
                <div class="hash-section">
                    <strong>File Hash (MD5):</strong> {conv['file_hash']}
                </div>
                
                <div class="messages">
"""
            
            for msg in conv['messages']:
                role = msg['role']
                timestamp = self.format_timestamp(msg['timestamp'])
                content = msg['content']
                
                if 'images' in msg:
                    for img in msg['images']:
                        img_info = f"\n\n[IMAGE REFERENCE - Cloud Storage]\n"
                        if 'image_title' in msg:
                            img_info += f"Title: {msg['image_title']}\n"
                        img_info += f"Asset: {img['asset_pointer']}\n"
                        img_info += f"Dimensions: {img['width']}x{img['height']}\n"
                        img_info += f"Size: {img['size_bytes']:,} bytes\n"
                        content = content.replace('[IMAGE_PLACEHOLDER]', img_info)
                
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
        
        html += f"""
        </div>
        
        <div class="footer">
            <p><strong>ChatGPT Forensic Analysis Report</strong></p>
            <p style="margin-top: 10px; opacity: 0.8; font-size: 0.9em;">
                This report contains extracted conversation data from ChatGPT mobile application backup files.<br>
                For forensic and investigative purposes only. Handle according to data protection regulations.
            </p>
            <div style="margin-top: 25px; padding-top: 20px; border-top: 1px solid #30363d;">
                <p style="margin-top: 5px; font-size: 0.85em;">
                    Report ID: {FileHasher.md5_string(datetime.now().isoformat())[:16].upper()}<br>
                    Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                    Copyright © 2026 North Loop Consulting. All rights reserved.
                </p>
            </div>
        </div>
    </div>
    
    <script>
        function toggleConversation(id) {{
            const conv = document.getElementById('conv-' + id);
            conv.classList.toggle('collapsed');
        }}
        
        function highlightText(text, searchTerm) {{
            if (!searchTerm) return text;
            const lowerText = text.toLowerCase();
            const lowerSearch = searchTerm.toLowerCase();
            let result = '';
            let lastIndex = 0;
            let index = lowerText.indexOf(lowerSearch);
            
            while (index !== -1) {{
                result += text.substring(lastIndex, index);
                result += '<span class="highlight">' + text.substring(index, index + searchTerm.length) + '</span>';
                lastIndex = index + searchTerm.length;
                index = lowerText.indexOf(lowerSearch, lastIndex);
            }}
            result += text.substring(lastIndex);
            return result;
        }}
        
        function searchMessages() {{
            const searchInput = document.getElementById('searchInput');
            const searchTerm = searchInput.value.toLowerCase();
            const messages = document.querySelectorAll('.message');
            const conversations = document.querySelectorAll('.conversation');
            let matchCount = 0;
            let hiddenConvCount = 0;
            
            if (searchTerm === '') {{
                messages.forEach(msg => {{
                    const content = msg.querySelector('.message-content');
                    const original = content.getAttribute('data-original');
                    if (original) {{
                        content.innerHTML = original;
                    }}
                    msg.classList.remove('hidden');
                }});
                conversations.forEach(conv => {{
                    conv.style.display = 'block';
                    conv.classList.remove('collapsed');
                }});
                document.getElementById('searchStats').textContent = '';
                return;
            }}
            
            conversations.forEach(conv => {{
                let convHasMatch = false;
                const convMessages = conv.querySelectorAll('.message');
                
                convMessages.forEach(msg => {{
                    const content = msg.querySelector('.message-content');
                    const role = msg.querySelector('.message-role');
                    const text = content.textContent.toLowerCase();
                    const roleText = role.textContent.toLowerCase();
                    
                    if (text.includes(searchTerm) || roleText.includes(searchTerm)) {{
                        msg.classList.remove('hidden');
                        convHasMatch = true;
                        matchCount++;
                        
                        if (!content.getAttribute('data-original')) {{
                            content.setAttribute('data-original', content.innerHTML);
                        }}
                        const original = content.getAttribute('data-original');
                        const highlighted = highlightText(original, searchTerm);
                        content.innerHTML = highlighted;
                    }} else {{
                        msg.classList.add('hidden');
                    }}
                }});
                
                if (convHasMatch) {{
                    conv.style.display = 'block';
                    conv.classList.remove('collapsed');
                }} else {{
                    conv.style.display = 'none';
                    hiddenConvCount++;
                }}
            }});
            
            const totalConvs = conversations.length;
            const visibleConvs = totalConvs - hiddenConvCount;
            document.getElementById('searchStats').textContent = 
                'Found ' + matchCount + ' message' + (matchCount !== 1 ? 's' : '') + ' in ' + visibleConvs + ' conversation' + (visibleConvs !== 1 ? 's' : '');
        }}
        
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape') {{
                const searchInput = document.getElementById('searchInput');
                if (searchInput.value !== '') {{
                    searchInput.value = '';
                    searchMessages();
                }} else {{
                    document.querySelectorAll('.conversation').forEach(conv => {{
                        conv.classList.add('collapsed');
                    }});
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        if self.logger:
            self.logger.info(f"HTML report generated: {output_file}")
    
    def escape_html(self, text):
        """Escape HTML special characters."""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='ChatGPT iOS Conversation Extractor - Forensic Edition',
        epilog='Example: %(prog)s -c CASE-2026-001 -e EVIDENCE-123 -x "John Smith" /path/to/backup'
    )
    
    # Required
    parser.add_argument('backup_path', help='Path to iOS backup directory containing ChatGPT data')
    
    # Case Management
    parser.add_argument('-c', '--case-number', help='Case number for tracking')
    parser.add_argument('-e', '--evidence-id', help='Evidence identifier')
    parser.add_argument('-x', '--examiner', help='Examiner name')
    parser.add_argument('-n', '--notes', help='Case notes or description')
    
    # Output Options
    parser.add_argument('-o', '--output', default='chatgpt_forensic_report', help='Output filename prefix (default: chatgpt_forensic_report)')
    parser.add_argument('-f', '--format', nargs='+', choices=['html', 'json', 'csv'], default=['html'], 
                        help='Output format(s) (default: html)')
    parser.add_argument('--no-hash', action='store_true', help='Skip file hash computation')
    
    # Filtering
    parser.add_argument('--date-from', help='Extract conversations from this date (YYYY-MM-DD)')
    parser.add_argument('--date-to', help='Extract conversations to this date (YYYY-MM-DD)')
    
    # Logging
    parser.add_argument('-l', '--log', default='forensic_extraction.log', help='Audit log file (default: forensic_extraction.log)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (errors only)')
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Setup logger
    logger = ForensicLogger(args.log)
    
    if args.quiet:
        logger.logger.setLevel(logging.ERROR)
    elif args.verbose:
        logger.logger.setLevel(logging.DEBUG)
    
    # Log start
    logger.info("=" * 80)
    logger.info("ChatGPT iOS Conversation Extractor - Forensic Edition v2.0")
    logger.info("=" * 80)
    
    # Build case info
    case_info = {
        'case_number': args.case_number or 'N/A',
        'evidence_id': args.evidence_id or 'N/A',
        'examiner': args.examiner or 'N/A',
        'exam_date': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'notes': args.notes or 'N/A',
        'tool_version': '2.0 Forensic Edition'
    }
    
    logger.info(f"Case Number: {case_info['case_number']}")
    logger.info(f"Evidence ID: {case_info['evidence_id']}")
    logger.info(f"Examiner: {case_info['examiner']}")
    
    # Find conversations directory
    backup_path = Path(args.backup_path)
    app_support_dir = backup_path / "Library" / "Application Support"
    
    conversations_dir = None
    if app_support_dir.exists():
        conv_dirs = list(app_support_dir.glob('conversations-v3-*'))
        if not conv_dirs:
            conv_dirs = list(app_support_dir.glob('conversations-*'))
        if conv_dirs:
            conv_dirs_with_content = []
            for d in conv_dirs:
                json_files = list(d.glob('*.json'))
                if json_files:
                    priority = 0 if 'default' not in d.name.lower() else 1
                    conv_dirs_with_content.append((priority, len(json_files), d))
            
            if conv_dirs_with_content:
                conv_dirs_with_content.sort(key=lambda x: (x[0], -x[1]))
                conversations_dir = conv_dirs_with_content[0][2]
    
    if not conversations_dir or not conversations_dir.exists():
        logger.critical(f"No conversations directory found in {app_support_dir}")
        sys.exit(1)
    
    logger.info(f"Source directory: {conversations_dir}")
    
    # Parse date filters
    date_from = None
    date_to = None
    if args.date_from:
        try:
            date_from = datetime.strptime(args.date_from, '%Y-%m-%d')
            logger.info(f"Filtering from: {args.date_from}")
        except ValueError:
            logger.error("Invalid date format for --date-from. Use YYYY-MM-DD")
            sys.exit(1)
    
    if args.date_to:
        try:
            date_to = datetime.strptime(args.date_to, '%Y-%m-%d')
            logger.info(f"Filtering to: {args.date_to}")
        except ValueError:
            logger.error("Invalid date format for --date-to. Use YYYY-MM-DD")
            sys.exit(1)
    
    # Extract conversations
    logger.info("Beginning extraction...")
    extractor = ConversationExtractor(conversations_dir, logger=logger, case_info=case_info)
    extractor.extract_all(date_from=date_from, date_to=date_to, compute_hashes=not args.no_hash)
    
    # Generate reports
    output_dir = Path.cwd()
    
    if 'html' in args.format:
        html_file = output_dir / f"{args.output}.html"
        logger.info(f"Generating HTML report: {html_file}")
        extractor.generate_html_report(html_file)
    
    if 'json' in args.format:
        json_file = output_dir / f"{args.output}.json"
        logger.info(f"Generating JSON export: {json_file}")
        extractor.export_to_json(json_file)
    
    if 'csv' in args.format:
        csv_file = output_dir / f"{args.output}.csv"
        logger.info(f"Generating CSV export: {csv_file}")
        extractor.export_to_csv(csv_file)
    
    # Final summary
    logger.info("=" * 80)
    logger.info("EXTRACTION COMPLETE")
    logger.info("=" * 80)
    logger.info(f"Total conversations: {extractor.extraction_stats['total_conversations']}")
    logger.info(f"Total messages: {extractor.extraction_stats['total_messages']}")
    logger.info(f"Files processed: {extractor.extraction_stats['processed_files']}")
    logger.info(f"Files failed: {extractor.extraction_stats['failed_files']}")
    
    if extractor.extraction_stats['errors']:
        logger.warning(f"Errors encountered: {len(extractor.extraction_stats['errors'])}")
        for error in extractor.extraction_stats['errors'][:5]:
            logger.warning(f"  - {error}")
    
    logger.info(f"Audit log: {args.log}")
    logger.info("=" * 80)

if __name__ == "__main__":
    main()
