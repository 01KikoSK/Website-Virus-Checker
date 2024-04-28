import requests

def check_for_viruses(url):
    api_key = 'YOUR_API_KEY'  # Replace with your VirusTotal API key
    api_url = f'https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={url}'
    
    response = requests.get(api_url)
    data = response.json()
    
    if data['positives'] > 0:
        print(f"The website may contain viruses. {data['positives']} out of {data['total']} scans detected malicious content.")
    else:
        print("The website is safe.")

check_for_viruses('https://example.com')  # Replace with the URL you want to check
