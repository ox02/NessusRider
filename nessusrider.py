import os
import argparse
import urllib3
import google.generativeai as genai

from nessus import Nessus
from ghostwriter import Ghostwriter
from utils import *

logger = setup_logger()


def main(scan_id, re_id, language, verify_ssl):
    logger.info("Config Session")
    access_key = os.getenv("NESSUS_API_KEY")
    secret_key = os.getenv("NESSUS_API_SECRET_KEY")
    nessus_url = os.getenv("NESSUS_URL")
    ghostwriter_url = os.getenv("GHOSTWRITER_URL")
    ghostwriter_api_key = os.getenv("GHOSTWRITER_API_KEY")
    gemini_api_key = os.getenv("GEMINI_API_KEY")

    if not all([access_key, secret_key, nessus_url, ghostwriter_url, ghostwriter_api_key, gemini_api_key]):
        logger.error("Environment variables for Nessus, Ghostwriter, or Gemini API are not set.")
        return

    genai.configure(api_key=gemini_api_key)
    # TODO: put parameter in config file
    gemini_model = genai.GenerativeModel("gemini-1.5-flash")

    nessus_client = Nessus(nessus_url=nessus_url, access_key=access_key, secret_key=secret_key, verify_ssl=verify_ssl)
    ghostwriter_client = Ghostwriter(ghostwriter_url=ghostwriter_url, ghostwriter_api_key=ghostwriter_api_key,
                                     verify_ssl=verify_ssl)

    logger.info("Starting main program...")

    logger.info(f"Fetching data for Nessus scan ID: {scan_id}")

    vulnerabilities = nessus_client.get_nessus_multiscans_data(scan_id.split(','))
    save_to_json(vulnerabilities)

    # findings_ghostwriter = convert_findings(vulnerabilities[-3:], re_id, gemini_model, language) # for testing purpose on only 2 findings

    findings_ghostwriter = convert_findings(vulnerabilities, re_id, gemini_model, language)

    ghostwriter_client.update_findings(findings_ghostwriter)


if __name__ == "__main__":
    print(colored_art("Nessus Rider", style="starwars"))
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(description="Nessus to Ghostwriter Import Tool")
    parser.add_argument("-nessus_scan_ids", type=str, required=True,
                        help="The ID of the Nessus scan (if you have multiple scans separated by comma)")
    parser.add_argument("-ghostwriter_project_id", type=str, required=True, help="The ID of the Ghostwriter project")
    parser.add_argument("-insecure", action="store_false", help="Disable SSL certificate verification")
    parser.add_argument("-language", type=str, default="english", help="The language (default: English)")
    args = parser.parse_args()

    main(args.nessus_scan_ids, args.ghostwriter_project_id, args.language, args.insecure)
