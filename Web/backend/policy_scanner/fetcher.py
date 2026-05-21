import logging
import time
import requests
from bs4 import BeautifulSoup
from typing import Optional
from urllib.parse import urljoin, urlparse
import yaml
import os

from .exceptions import PolicyFetchError

logger = logging.getLogger(__name__)

class PolicyFetcher:
    def __init__(self, config_path: str = None):
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.timeout = self.config.get('timeout_seconds', 10)
        self.user_agents = self.config.get('user_agents', [])
        self.paths_to_check = self.config.get('paths_to_check', ['/privacy', '/privacy-policy', '/terms', '/legal'])

    def find_policy_url(self, base_url: str) -> Optional[str]:
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'https://' + base_url

        # Check common paths
        for path in self.paths_to_check:
            test_url = urljoin(base_url, path)
            try:
                # Use a basic GET request to check if it exists
                headers = {'User-Agent': self.user_agents[0] if self.user_agents else 'Mozilla/5.0'}
                response = requests.head(test_url, timeout=self.timeout, headers=headers, allow_redirects=True)
                if response.status_code == 200:
                    return test_url
            except requests.RequestException as e:
                logger.debug(f"Failed to check {test_url}: {e}")
        
        # Scrape homepage for links
        try:
            headers = {'User-Agent': self.user_agents[0] if self.user_agents else 'Mozilla/5.0'}
            response = requests.get(base_url, timeout=self.timeout, headers=headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    text = a_tag.get_text().lower()
                    if 'privacy' in text or 'policy' in text or 'terms' in text or 'legal' in text:
                        return urljoin(base_url, a_tag['href'])
        except requests.RequestException as e:
            logger.error(f"Failed to scrape homepage {base_url}: {e}")
            raise PolicyFetchError(f"Network error while finding policy URL for {base_url}")

        return None

    def fetch_policy_text(self, url: str) -> Optional[str]:
        try:
            headers = {'User-Agent': self.user_agents[0] if self.user_agents else 'Mozilla/5.0'}
            response = requests.get(url, timeout=self.timeout, headers=headers)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            # Kill all script and style elements
            for script in soup(["script", "style"]):
                script.extract()
                
            text = soup.get_text(separator=' ')
            # collapse whitespace
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = '\n'.join(chunk for chunk in chunks if chunk)
            
            return text
        except requests.RequestException as e:
            logger.error(f"Failed to fetch policy text from {url}: {e}")
            raise PolicyFetchError(f"Network error while fetching policy from {url}")
