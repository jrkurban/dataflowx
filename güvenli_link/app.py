import requests
from bs4 import BeautifulSoup
from flask import Flask, request, render_template
from urllib.parse import urljoin

app = Flask(__name__)


@app.route('/')
def home():
    return render_template('index.html')

def extract_urls(page_url):
    response = requests.get(page_url)
    soup = BeautifulSoup(response.text, 'html.parser')

    url = set()

    for a in soup.find_all('a', href=True):
        full_url = urljoin(page_url, a['href'])
        url.add(full_url)

    return list(url)


def scan_url_with_virustotal(url):
    VIRUSTOTAL_API_KEY = '54f738b81a18594d278037ff0b281210c5ea94550cc1f543e038e43c96daa04d'

    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    scan_url = 'https://www.virustotal.com/api/v3/urls'

    # Encode the URL in base64 as per API v3 requirements
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    response = requests.get(f'{scan_url}/{url_id}', headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        positives = stats.get('malicious', 0)
        total = stats.get('total', 0)

        if positives == 0:
            message = "No malware detected in URL"
        else:
            message = f"Malware detected in URL: {positives} out of {total} scans"

        return {
            'url': url,
            'positives': positives,
            'total': total,
            'message': message
        }
    elif response.status_code == 404:
        return {
            'url': url,
            'positives': "N/A",
            'total': "N/A",
            'message': "URL not found in VirusTotal database"
        }
    else:
        return {
            'url': url,
            'positives': "N/A",
            'total': "N/A",
            'message': f"Failed request with status code {response.status_code}"
        }

@app.route('/', methods=['POST'])
def index():
    page_url = request.form['page_url']
    urls = extract_urls(page_url)
    scan_results = [scan_url_with_virustotal(url) for url in urls]
    return render_template('results.html', urls=urls, scan_results=scan_results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
