from time import sleep

import requests

from logger_config import setup_logger

logger = setup_logger(name="ghostwriter")


class Ghostwriter:
    def __init__(self, ghostwriter_url, ghostwriter_api_key, verify_ssl=True):
        """
        Initialize the GhostwriterClient instance.

        Parameters:
        - ghostwriter_url (str): Base URL of the Ghostwriter GraphQL API endpoint.
        - ghostwriter_api_key (str): API key for Bearer token authentication.
        - verify_ssl (bool): If False, disables SSL certificate verification.
        """
        self.ghostwriter_url = ghostwriter_url
        self.ghostwriter_api_key = ghostwriter_api_key
        self.verify_ssl = verify_ssl
        self.headers = {
            "Authorization": f"Bearer {self.ghostwriter_api_key}",
            "Content-Type": "application/json"
        }

    def insert_findings(self, findings_data):
        """
        Send a GraphQL mutation to insert a report of findings into the Ghostwriter API.

        Parameters:
        - findings_data (list): List of findings to be inserted.

        Returns:
        - dict: Response data from the Ghostwriter API or None if an error occurs.
        """
        url = f"{self.ghostwriter_url}/v1/graphql"
        query = """
        mutation InsertFindings($findings: [reportedFinding_insert_input!]!) {
          insert_reportedFinding(objects: $findings) {
            returning {
              id
              title
              cvssScore
              position
            }
          }
        }
        """
        for finding in findings_data:
            variables = {"findings": finding}
            payload = {"query": query, "variables": variables}

            try:
                response = requests.post(url, headers=self.headers, json=payload, verify=self.verify_ssl)
                # this crap is because otherwise the order of the findings entered is not respected
                sleep(1)
                response.raise_for_status()

                response_data = response.json()
                if response.status_code == 200 and "errors" not in response_data:
                    title = finding["title"]
                    logger.info(f"{title} inserted successfully into Ghostwriter")
                    logger.debug(f"Response: {response_data}")
                    # return response_data

                else:
                    logger.error(f"Failed to insert data. Response: {response_data}")
                    # return None

            except requests.exceptions.RequestException as e:
                logger.error(f"An error occurred while updating Ghostwriter: {e}")
                # return None

    def update_findings(self, findings_data):
        return None

    def test_connection(self):
        return None
