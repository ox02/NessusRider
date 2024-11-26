import json
import os

from tqdm import tqdm
from time import sleep
from art import text2art
from logger_config import setup_logger
from google.generativeai.types import HarmCategory, HarmBlockThreshold

logger = setup_logger(name="Utils")

# Define ANSI color codes
COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "reset": "\033[0m"
}


def colored_art(text, style="block", color="blue"):
    """
    Create colored ASCII art text using the `art` library and ANSI colors.

    Parameters:
    - text (str): The text to display as ASCII art.
    - style (str): The art style from `art.text2art`.
    - color (str): The color to apply (red, green, yellow, blue, magenta, cyan).

    Returns:
    - str: ASCII art text with the specified color applied.
    """
    art_text = text2art(text, font=style)
    color_code = COLORS.get(color, COLORS["reset"])
    return f"{color_code}{art_text}{COLORS['reset']}"


def save_to_json(data, filename="file.json"):
    """
    Save the list of vulnerabilities to a JSON file.
    """
    try:
        with open(filename, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        logger.info(f"Data saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving data to JSON: {e}")


def convert_findings(input_data, report_id, gemini_model, language):
    findings = []
    quota_tier_gemini = 0
    # for item in input_data:
    for item in tqdm(input_data, desc="Findings ", ncols=100, position=0, dynamic_ncols=True):
        output = item['outputs']
        plugin_description = item['info']['plugindescription']

        # todo put parameters in config file
        if plugin_description['severity'] >= 1:
            # Extract risk information
            cvss_vector, cvss_score = extract_risk_info(plugin_description)

            # Build affected entities table
            affected_entities_out = build_affected_entities_table(output)

            plugin_output = build_plugins_output(output)

            # Generate references
            references_output = build_references(plugin_description)

            # Create finding entry
            if language.lower() == "english":
                finding = create_finding_entry(
                    plugin_description['pluginname'], report_id, plugin_description['severity'] + 1,
                    affected_entities_out, cvss_score, cvss_vector, references_output,
                    str(plugin_description['pluginattributes']['description']),
                    str(plugin_description['pluginattributes'].get('solution', '')),
                    plugin_output
                )
            else:
                # todo add log and put parameters in config file
                if quota_tier_gemini > 14:
                    logger.info(f"Gemini tier quota reached. Let's wait 90 seconds. Quota: {quota_tier_gemini}")
                    sleep(75)
                    quota_tier_gemini = 0

                translated_description, translate_mitigation, translated = get_translation(plugin_description,
                                                                                           gemini_model,
                                                                                           language,
                                                                                           "translation.json")
                if translated <= 0:
                    quota_tier_gemini += 2  # todo put parameters in config file

                if translated == -1:
                    plugin_description['pluginname'] = plugin_description['pluginname'] + " [ENGLISH]"

                finding = create_finding_entry(
                    plugin_description['pluginname'], report_id, plugin_description['severity'] + 1,
                    affected_entities_out, cvss_score, cvss_vector, references_output,
                    translated_description,
                    translate_mitigation,
                    plugin_output
                )

            findings.append(finding)
        else:
            logger.info(f"Skipping {plugin_description['pluginname']} id: {plugin_description['pluginid']}")

    findings = sorted(findings, key=lambda x: float(x['cvssScore']), reverse=True)
    for position, finding in enumerate(findings):
        finding['position'] = position + 1
    return findings


def get_translation(plugin_description, gemini_model, language, translations_file):
    translations = load_translations(translations_file)

    # todo: put in a config file
    gemini_model_safety_settings = {HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                                    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                                    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE, }

    key = (plugin_description['pluginid'], language)

    # Check if translation exists
    if key in translations:
        logger.info(
            f"Plugin already translated: id={plugin_description['pluginid']}, name={plugin_description['pluginattributes']['plugin_name']}")
        return translations[key]['description'], translations[key]['mitigation'], 1

    # todo add error maanagements.
    try:
        logger.info(
            f"Translate new plugin: id={plugin_description['pluginid']}, name={plugin_description['pluginattributes']['plugin_name']}")
        logger.debug(f"Translate this text: {plugin_description['pluginattributes']['description']}")

        translated_description = gemini_model.generate_content(
            "Translate the following text into " + language + " : " + str(
                plugin_description['pluginattributes']['description']), safety_settings=gemini_model_safety_settings)

        # sleep(1)

        logger.debug(f"Translate this text: {plugin_description['pluginattributes'].get('solution', '')}")
        translate_mitigation = gemini_model.generate_content(
            "Translate the following text into " + language + " : " + str(
                plugin_description['pluginattributes'].get('solution', '')),
            safety_settings=gemini_model_safety_settings)

        save_translation(plugin_description['pluginid'], language, translated_description.text,
                         translate_mitigation.text,
                         translations_file)

    except Exception as e:
        logger.error(f"Error fetching traslantion from Gemini API: {e}, skip the translation.. ")
        return str(plugin_description['pluginattributes']['description']), str(
            plugin_description['pluginattributes'].get('solution', '')), -1

    return translated_description.text, translate_mitigation.text, 0


def load_translations(file_path):
    """
    Load existing translations from a JSON file and return them as a dictionary.
    """
    translations = {}
    if os.path.exists(file_path):
        with open(file_path, mode="r", encoding="utf-8") as jsonfile:
            data = json.load(jsonfile)
            for entry in data:
                key = (entry["plugin_id"], entry["language"])
                translations[key] = {
                    "description": entry["translated_description"],
                    "mitigation": entry["translate_mitigation"]
                }
    return translations


def save_translation(plugin_id, language, translated_description, translated_mitigation, file_path):
    """
    Save a new translation to the JSON file.
    """
    logger.info(f"Saving translation to {file_path} ")
    new_translation = {
        "plugin_id": plugin_id,
        "language": language,
        "translated_description": translated_description.strip(),
        "translate_mitigation": translated_mitigation
    }

    if os.path.exists(file_path):
        # Se il file esiste, carica i dati esistenti e aggiungi la nuova traduzione
        with open(file_path, mode="r", encoding="utf-8") as jsonfile:
            data = json.load(jsonfile)
        data.append(new_translation)
    else:
        # Se il file non esiste, crea una lista con la nuova traduzione
        data = [new_translation]

    # Salva i dati aggiornati nel file JSON
    with open(file_path, mode="w", encoding="utf-8") as jsonfile:
        json.dump(data, jsonfile, ensure_ascii=False, indent=4)


def extract_risk_info(plugin_description):
    """
    Extract CVSS vector and CVSS score from plugin description.
    """
    risk_info = plugin_description.get('pluginattributes', {}).get('risk_information', {})
    cvss_vector = risk_info.get('cvss3_vector') or risk_info.get('cvss_vector', "Not Provided")
    cvss_score = float(risk_info.get('cvss3_base_score', "0.0")) or float(risk_info.get('cvss_base_score', "0.0"))
    return cvss_vector, cvss_score


def build_affected_entities_table(outputs):
    """
    Build an HTML table of affected entities based on output data.
    """
    combined_ports = {}

    for entry in outputs:
        for port, hosts in entry["ports"].items():
            if port not in combined_ports:
                combined_ports[port] = []  # Inizializza una lista se la porta non esiste
            combined_ports[port].extend(hosts)

    table_html = "<table border='1'><thead><tr><th>Hostnames</th><th>Port</th><th>Protocol</th></tr></thead><tbody>"

    for port, hosts in combined_ports.items():
        port_number, protocol, _ = port.split(" / ")
        hostnames = "<br>".join([host["hostname"] for host in hosts])
        table_html += f"<tr><td>{hostnames}</td><td>{port_number}</td><td>{protocol}</td></tr>"

    table_html += "</tbody></table>"
    return table_html


def build_plugins_output(outputs):
    plugins_output = ""
    for output in outputs:
        tmp = ""
        for port, hosts in output["ports"].items():
            for host in hosts:
                hostname = host["hostname"]
                port_number, protocol, _ = port.split(" / ")
                tmp = tmp + f"{hostname}:{port_number}<br>"
        tmp = tmp + output["plugin_output"] + "<br><br>"
        plugins_output += tmp
    return plugins_output


def build_references(plugin_description):
    """
    Generate a string of references from plugin description.
    """
    references = []

    # Extract main reference information
    ref_info = plugin_description.get("ref_information", {}).get("ref", [])
    for ref in ref_info:
        url_base = ref["url"]
        for value in ref["values"]["value"]:
            references.append(f"- {url_base}{value}")

    # Extract 'see also' links
    see_also = plugin_description.get('pluginattributes', {}).get("see_also", [])
    for url in see_also:
        references.append(f"- {url}")

    return "<br>".join(references)


def create_finding_entry(plugin_name, report_id, severity, affected_entities, cvss_score, cvss_vector,
                         references, plugin_description, plugin_mitigation, replication_steps):
    """
    Create a dictionary entry for a single finding.
    """
    return {
        "title": plugin_name,
        "reportId": report_id,
        "findingTypeId": 1,
        "severityId": severity,
        "affectedEntities": affected_entities,
        "description": plugin_description,
        "mitigation": plugin_mitigation,
        "cvssScore": cvss_score,
        "cvssVector": str(cvss_vector),
        "references": str(references),
        "replication_steps": replication_steps,
        "position": 0
    }
