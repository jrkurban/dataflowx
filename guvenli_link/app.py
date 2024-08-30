import base64
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template
from urllib.parse import urljoin

app = Flask(__name__)

VIRUSTOTAL_API_KEY = '54f738b81a18594d278037ff0b281210c5ea94550cc1f543e038e43c96daa04d'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls'


@app.route('/')
def home():
    return render_template('index.html')


def extract_urls(page_url):
    """Extracts and returns a list of unique absolute URLs from the given webpage."""
    response = requests.get(page_url)
    soup = BeautifulSoup(response.text, 'html.parser')

    urls = {urljoin(page_url, a['href']) for a in soup.find_all('a', href=True)}

    return list(urls)


def scan_url_with_virustotal(url):
    """Scans a URL using the VirusTotal API and returns the scan results."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(f'{VIRUSTOTAL_URL}/{url_id}', headers={'x-apikey': VIRUSTOTAL_API_KEY})

    if response.status_code == 200:
        stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        positives, total = stats.get('malicious', 0), stats.get('total', 0)
        message = "No malware detected in URL" if positives == 0 else f"Malware detected in URL: {positives} out of {total} scans"
    elif response.status_code == 404:
        positives, total, message = "N/A", "N/A", "URL not found in VirusTotal database"
    else:
        positives, total, message = "N/A", "N/A", f"Failed request with status code {response.status_code}"

    return {'url': url, 'positives': positives, 'total': total, 'message': message}


@app.route('/', methods=['POST'])
def index():
    page_url = request.form['page_url']
    urls = extract_urls(page_url)
    scan_results = [scan_url_with_virustotal(url) for url in urls]
    return render_template('results.html', urls=urls, scan_results=scan_results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
