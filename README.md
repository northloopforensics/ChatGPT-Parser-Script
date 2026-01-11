# ChatGPT iOS Forensic Extraction Tool

**By North Loop Consulting**  
**Version 1.0**  
**Date: January 11, 2026**

## Overview

This script is provided as a simple proof-of-concept for research on the ChatGPT iOS app. For that reason you may need to move some data around or even rename the root folder cotaining the apps data for it to operate correctly. 
This tool extracts and analyzes conversation data from ChatGPT iOS application backups. It parses the complex tree-based JSON storage format used by the ChatGPT mobile app and generates a comprehensive forensic report suitable for digital investigations.

## Features

- **Complete Conversation Extraction**: Retrieves all user prompts, assistant responses, and tool interactions
- **Audio Transcription Support**: Extracts voice mode conversation transcripts
- **Device Attribution**: Parses Segment analytics for comprehensive device profiling
- **Image Metadata**: Documents AI-generated image references (stored remotely)
- **Flexible GUID Detection**: Automatically detects conversation folders regardless of device-specific GUID
- **Interactive HTML Report**: Generates searchable report with keyword highlighting
- **Timestamp Conversion**: Converts Apple Cocoa timestamps to human-readable format
- **Dark Mode Interface**: Professional forensic report styling

## Requirements

- Python 3.6 or higher
- Standard library only (no external dependencies)
- iOS backup extracted from iTunes/Finder backup

## Installation

No installation required. Simply place `extract_conversations.py` in the root of your extracted iOS backup folder.

The script uses the default Python library so there is no requirements.txt to content with. 

## Directory Structure

The tool expects the following iOS backup structure:

```
AppDomain-com.openai.chat/
├── Library/
│   ├── Application Support/
│   │   ├── conversations-v3-{GUID}/        # Conversation JSON files
│   │   ├── segment/oai/                     # Device analytics
│   │   └── gizmos-{GUID}/                   # Custom GPT data
│   ├── Preferences/                         # App preferences
│   └── Cookies/                             # Session data
└── Documents/
```

## Usage

### Basic Extraction

```bash
cd /path/to/AppDomain-com.openai.chat
python3 ChatGPT_IOS_parser.py
```

The tool will:
1. Automatically detect the conversations directory (handles any GUID)
2. Extract all conversations with full metadata
3. Parse device information from Segment analytics
4. Generate `chatgpt_forensic_report.html` in the current directory

### Output

The generated report includes:

- **Report Summary**: Total conversations, messages, and user prompts
- **Device Information**: Model, OS version, screen resolution, app version, device/user IDs
- **Conversation Details**: Expandable conversations with searchable content
- **Search Functionality**: Real-time filtering with keyword highlighting
- **Timestamps**: All dates in human-readable format
- **Image References**: Metadata for AI-generated images (with cloud storage note)


## Forensic Artifacts Extracted

### 1. Conversation Data
- Full text of all messages
- Message timestamps (converted from Apple Cocoa format)
- Message authorship (user/assistant/tool)
- Conversation titles and metadata
- Model identifiers used

### 2. Audio Transcriptions
- Voice mode conversation text
- Transcribed prompts and responses
- Note: Raw audio is NOT stored locally

### 3. Image Generation Metadata
- Asset pointers (sediment:// protocol)
- Image dimensions and file sizes
- DALL-E generation IDs
- Note: Actual images stored on OpenAI servers only

### 4. Device Information
- Device model and manufacturer
- iOS version and build
- Application version and build
- Screen resolution
- Device UUID
- User account ID
- Timezone and locale

## Search Functionality

The HTML report includes a search feature:

- **Real-time filtering**: Results update as you type
- **Case-insensitive matching**: Finds content regardless of case
- **Keyword highlighting**: Matched terms highlighted in gray
- **Result statistics**: Shows number of matches found
- **Auto-expand**: Automatically expands conversations with matches
- **Clear search**: Press Escape to clear search

## Important Notes

### Image Storage
Generated images are **NOT** included in iOS backups. Only metadata references are preserved. To recover actual image content, you must:
- Screenshot images during device examination
- Contact OpenAI with generation IDs (legal proceedings)
- Check for cached images in device memory (if not backed up)

### Deleted Conversations
Once deleted in the ChatGPT app, conversations are removed from subsequent backups. There is no deleted items recovery.

### Voice Audio
Raw audio from voice mode conversations is **NOT** stored. Only text transcriptions are preserved.

### Multiple Accounts
- The tool automatically detects multiple user accounts
- Prioritizes non-default folders with actual content
- Reports which conversation folder is being used

## Technical Details

### Timestamp Format
Apple Cocoa NSDate format: seconds since January 1, 2001 00:00:00 UTC

Conversion to Unix epoch:
```
Unix Timestamp = Cocoa Timestamp + 978307200
```

### Tree Structure Parsing
Conversations use a non-sequential tree structure:
1. Messages stored as nodes in alternating ID/data array
2. Parent-child relationships define conversation flow
3. Recursive traversal reconstructs chronological order
4. Multiple content types handled (text, audio_transcription, image_asset_pointer)

### GUID Flexibility
The tool uses pattern matching to find conversation folders:
- Pattern: `conversations-v3-*`
- Prioritizes folders with content
- Prefers non-default (user account) folders
- Handles any device/account GUID automatically

## Output Files

- `chatgpt_forensic_report.html` - Main forensic report (standalone, no external dependencies)

## Troubleshooting

### "No conversations directory found"
- Ensure you're running the script from the AppDomain-com.openai.chat root
- Verify the backup contains Library/Application Support/conversations-v3-* folders
- Check that JSON files exist in the conversations directory

### "Processed 0 conversations"
- The tool found a conversations folder but it's empty
- Try checking if multiple folders exist (may have selected empty default folder)
- Verify JSON files are valid and not corrupted

### Device information shows "Unknown"
- Segment analytics files may be missing or corrupted
- Check Library/Application Support/segment/oai/ for JSON files
- Some older backups may not have complete Segment data


## Version History

### Version 1.0 (January 11, 2026)
- Initial release
- Full conversation extraction
- Audio transcription support
- Device information parsing from Segment analytics
- Interactive HTML report with search
- Flexible GUID detection
- Image metadata documentation


**North Loop Consulting**  
Copyright 2026. All rights reserved.

## License

This tool is provided for professional forensic use. Commercial redistribution requires permission from North Loop Consulting.

---

## Quick Reference

### Common Commands

Extract conversations:
```bash
python3 ChatGPT_IOS_parser.py
```

View report:
```bash
open chatgpt_forensic_report.html
```

### Key Files

- `ChatGPT_IOS_parser.py` - Main extraction script
- `chatgpt_forensic_report.html` - Generated forensic report

### Key Directories

- `Library/Application Support/conversations-v3-{GUID}/` - Conversation data
- `Library/Application Support/segment/oai/` - Device telemetry
- `Library/Preferences/` - App configuration
- `Library/Cookies/` - Authentication data
