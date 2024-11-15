import requests

from logger_config import setup_logger

logger = setup_logger(name="nessus")


class Nessus:
    def __init__(self, nessus_url, access_key, secret_key, verify_ssl=True):
        """
        Initialize the NessusClient instance.

        Parameters:
        - nessus_url (str): Base URL of the Nessus instance.
        - access_key (str): Nessus access key for authentication.
        - secret_key (str): Nessus secret key for authentication.
        - verify_ssl (bool): If False, SSL certificate verification is disabled.
        """
        self.nessus_url = nessus_url
        self.access_key = access_key
        self.secret_key = secret_key
        self.verify_ssl = verify_ssl
        self.headers = {
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key};"
        }

    def get_nessus_multiscans_data(self, scan_ids):
        """
        Fetch scan data from the Nessus API and return it as a list of vulnerabilities.

        TODO: improve efficiency

        Parameters:
        - scan_id (list): The list ID of the Nessus scans to retrieve.

        Returns:
        - List: A list containing the scan data with vulnerabilities and associated hosts.
        """
        vulnerability_details = []
        # plugin_dict = defaultdict(list)
        plugins = []
        for scan_id in scan_ids:
            url = f"{self.nessus_url}/scans/{scan_id}"
            try:
                response = requests.get(url, headers=self.headers, verify=self.verify_ssl)
                response.raise_for_status()
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])

                for vuln in vulnerabilities:
                    # if vuln['plugin_id'] == 57608:
                    plugins.append(
                        (scan_id, vuln['plugin_id'])
                    )

            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching scan data from Nessus API: {e}")

        for scan_id, plugin_id in plugins:
            plugin_data = self.get_plugin_data(scan_id, plugin_id)
            vuln_find = False
            for vuln in vulnerability_details:
                if vuln['info']['plugindescription']['pluginid'] == str(plugin_id):
                    vuln_find = True
                    vuln['outputs'].extend(plugin_data['outputs'])
                    break

            if not vuln_find:
                vulnerability_details.append(plugin_data)

        return vulnerability_details

    def get_nessus_scan_data(self, scan_id):
        """
        Fetch scan data from the Nessus API and return it as a list of vulnerabilities.

        Parameters:
        - scan_id (str): The ID of the Nessus scan to retrieve.

        Returns:
        - List: A list containing the scan data with vulnerabilities and associated hosts.
        """
        url = f"{self.nessus_url}/scans/{scan_id}"

        try:
            response = requests.get(url, headers=self.headers, verify=self.verify_ssl)
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            # Fetch detailed information for each vulnerability plugin
            vulnerability_details = [
                self.get_plugin_data(scan_id, vuln['plugin_id'])
                for vuln in vulnerabilities
            ]

            return vulnerability_details

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching scan data from Nessus API: {e}")
            return []

    def get_plugin_data(self, scan_id, plugin_id):
        """
        Fetch additional data for a specific plugin within a scan.

        Parameters:
        - scan_id (str): The ID of the Nessus scan.
        - plugin_id (str): The plugin ID for the vulnerability.

        Returns:
        - dict: A dictionary with plugin details or an empty dictionary on error.
        """
        plugin_url = f"{self.nessus_url}/scans/{scan_id}/plugins/{plugin_id}"

        try:
            response = requests.get(plugin_url, headers=self.headers, verify=self.verify_ssl)
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching plugin data for plugin ID {plugin_id}: {e}")
            return {}
