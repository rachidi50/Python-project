"""Optional public IP lookup; the local pipeline uses supplied country CSVs."""
import logging
import json
from ipaddress import ip_address
from urllib.request import urlopen


logger = logging.getLogger(__name__)


def geo_location(ip):
    try:
        address = ip_address(ip)
        with urlopen(f'https://ipinfo.io/{address}/json', timeout=10) as response:
            return json.load(response)
    except (ValueError, OSError) :
        logger.exception('Geolocation lookup failed')
        raise


if __name__ == '__main__':
    print(geo_location('88.147.153.239'))
