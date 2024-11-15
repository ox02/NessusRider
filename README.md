```
.__   __.  _______      _______.   _______. __    __      _______.    .______       __   _______   _______ .______      
|  \ |  | |   ____|    /       |  /       ||  |  |  |    /       |    |   _  \     |  | |       \ |   ____||   _  \     
|   \|  | |  |__      |   (----` |   (----`|  |  |  |   |   (----`    |  |_)  |    |  | |  .--.  ||  |__   |  |_)  |    
|  . `  | |   __|      \   \      \   \    |  |  |  |    \   \        |      /     |  | |  |  |  ||   __|  |      /     
|  |\   | |  |____ .----)   | .----)   |   |  `--'  |.----)   |       |  |\  \----.|  | |  '--'  ||  |____ |  |\  \----.
|__| \__| |_______||_______/  |_______/     \______/ |_______/        | _| `._____||__| |_______/ |_______|| _| `._____|
```

This Python tool automates the process of importing vulnerability data from Nessus into Ghostwriter, utilizing Google Gemini AI for natural language generation to enhance findings. The tool fetches scan data from the Nessus API, processes it, and uploads the findings to a specified Ghostwriter project.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Environment Variables](#environment-variables)
- [Notes](#notes)

## Features

- **Automated data import**: Pulls vulnerability data from Nessus, processes it, and pushes it to Ghostwriter.
- **Natural Language Generation**: Uses Google Gemini AI to reformat findings in a report-friendly manner.
- **Multi-scan support**: Accepts multiple scan IDs separated by commas.

## Requirements

- Python 3.7+
- Nessus API credentials
- Ghostwriter API credentials
- Google Gemini API Key

## Installation

1. Clone this repository.
    ```bash
    git clone <repository-url>
    cd <repository-name>
    ```
2. Install the dependencies.
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

This script requires several environment variables for authentication with Nessus, Ghostwriter, and Google Gemini.

**Set Environment Variables**  
   Update your shell environment or create an `.env` file with the following variables:
    - `NESSUS_API_KEY`: Your Nessus API access key
    - `NESSUS_API_SECRET_KEY`: Your Nessus API secret key
    - `NESSUS_URL`: The base URL for the Nessus API
    - `GHOSTWRITER_URL`: The base URL for Ghostwriter
    - `GHOSTWRITER_API_KEY`: Your Ghostwriter API key
    - `GEMINI_API_KEY`: Your Google Gemini API key

## Usage

Run the tool from the command line, passing in the required arguments:

```bash
python nessusrider.py -scan_id <scan_id> -project_id <project_id> [-insecure] [-language <language>]
```

### Arguments

- `-scan_id` (required): The ID of the Nessus scan(s) to process. Multiple scan IDs can be provided, separated by commas.
- `-project_id` (required): The ID of the Ghostwriter project where the findings will be added.
- `-insecure`: Disable SSL verification for API requests.
- `-language`: The language of the generated findings. Defaults to English.

### Example

```bash
python nessusrider.py -scan_id "12345,67890" -project_id "555" -language "italian"
```

## Environment Variables

| Variable                | Description                                         |
|-------------------------|-----------------------------------------------------|
| `NESSUS_API_KEY`        | Nessus API access key                               |
| `NESSUS_API_SECRET_KEY` | Nessus API secret key                               |
| `NESSUS_URL`            | Base URL for Nessus API                             |
| `GHOSTWRITER_URL`       | Base URL for Ghostwriter API                        |
| `GHOSTWRITER_API_KEY`   | Ghostwriter API access key                          |
| `GEMINI_API_KEY`        | Google Gemini API key for NLG                       |

## Notes

- Ensure that all required environment variables are set before running the script.
- SSL verification is enabled by default. Use the `-insecure` option to disable it if needed.
- The script requires `google.generativeai`, `urllib3`, and additional libraries listed in `requirements.txt`.
- The tool currently uses the `gemini-1.5-flash` model. Update the model version as necessary.

## Enhancements ideas

- Configuration files to centralized the customization.
- Make sure that only new vulnerabilities are added to the GhostWriter findings library, while existing ones are referenced in the report along with scan details.