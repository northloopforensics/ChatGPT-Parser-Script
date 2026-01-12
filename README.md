# ChatGPT iOS Forensic Extraction Tool

**By North Loop Consulting**  
**Version 2.0**  
**Date: January 11, 2026**
Tested on versions 1.2024.080 (Build 24781), 1.2025.350 (Build 20387701780)

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

## Usage
Below are the command line instructions for the script. The backup path should be the root folder for the app's data from either an iTunes backup or a full file system extraction. 
```
usage: ChatGPT_IOS_parser.py [-h] [-c CASE_NUMBER] [-e EVIDENCE_ID] [-x EXAMINER]
                                      [-n NOTES] [-o OUTPUT]
                                      [-f {html,json,csv} [{html,json,csv} ...]] [--no-hash]
                                      [--date-from DATE_FROM] [--date-to DATE_TO] [-l LOG] [-v]
                                      [-q]
                                      backup_path
```
For the CLI date filtering in ChatGPT_IOS_parser_forensic.py, the date format is:

YYYY-MM-DD (ISO 8601 standard)

Examples:

--date-from 2024-01-15
--date-to 2024-12-31


## Installation

No installation required. Simply place `extract_conversations.py` in the root of your extracted iOS backup folder.

The script uses the default Python library so there is no requirements.txt to content with. 

## Directory Structure

The tool expects similar iOS backup structure:

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


### Output

The generated HTML, JSON, or CSV reports include:

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

### Voice Audio
Raw audio from voice mode conversations is **NOT** stored. Only text transcriptions are preserved.

### Multiple Accounts
- The tool automatically detects multiple user accounts
- Prioritizes non-default folders with actual content
- Reports which conversation folder is being used

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


## Troubleshooting

### "No conversations directory found"
- Ensure you're running the script on the AppDomain-com.openai.chat root folder
- Verify the backup contains Library/Application Support/conversations* folders
- Check that JSON files exist in the conversations directory

### "Processed 0 conversations"
- The tool found a conversations folder but it's empty
- Try checking if multiple folders exist (may have selected empty default folder)
- Verify JSON files are valid and not corrupted

### Device information shows "Unknown"
- Segment analytics files may be missing or corrupted
- Check Library/Application Support/segment/oai/ for JSON files
- Some older backups may not have complete Segment data


**North Loop Consulting**  
Copyright 2026. All rights reserved.

## License

This tool is provided for professional forensic use. Commercial redistribution requires permission from North Loop Consulting.

---



- `Library/Application Support/conversations-v3-{GUID}/` - Conversation data
- `Library/Application Support/segment/oai/` - Device telemetry
- `Library/Preferences/` - App configuration
- `Library/Cookies/` - Authentication data
