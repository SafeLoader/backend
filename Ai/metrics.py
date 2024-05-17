from bs4 import BeautifulSoup
from bs4 import SoupStrainer
import requests


def get_shortening_services():
    url = "https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list"
    response = requests.get(url)
    # Split the response text by newlines to get a list of services
    services = response.text.split("\n")
    # Filter out any empty strings or comments
    services = [s for s in services if s and not s.startswith("#")]
    return services

shortening_services = get_shortening_services()


import re
# having_IP_Address
def having_ip_address(url):
    # Match both cases : decimal and hexadecimal IP address
    ip_address_pattern = r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}|0x([0-9A-Fa-f]{2})\.){3}0x([0-9A-Fa-f]{2})\b'
    match = re.search(ip_address_pattern, url)
    
    # If there is a match, it means there is an IP address in the URL
    if match:
        return -1
    else:
        return 1

def url_length(url):
    length=len(url)
    if length < 54:
        return 1
    else:
        return -1

def shortening_service(url):
    pattern = "|".join(map(re.escape, shortening_services))
    match = re.search(pattern, url)
    if match:
        return -1
    else:
        return 1

def having_at_symbol(url):
    match=re.search('@',url)
    if match:
        return -1
    else:
        return 1 

def double_slash_redirecting(url):
    #Since the position starts from 0, we have increased the range by 1
    list=[m.start() for m in re.finditer('//', url)]
    if list[len(list)-1]>6:
        return -1
    else:
        return 1

from urllib.parse import urlparse
# Prefix_Suffix
def prefix_suffix(url):
    if '-' in urlparse(url).netloc:
        return -1    # phishing
    else:
        return 1     # legitimate

# having_Sub_Domain
def having_sub_domain(url):
    length = len(urlparse(url).netloc.split('.'))
    if length == 2:
        return 1     # legitimate
    elif length == 3:
        return 0     # suspicious
    else:
        return -1    # phishing

# Domain_registeration_length
import whois
from datetime import datetime

def domain_registration_length(url):
    try:
        w = whois.whois(url)
        if w.expiration_date and isinstance(w.expiration_date, list):
            expiration_date = w.expiration_date[0]
        elif w.expiration_date:
            expiration_date = w.expiration_date
        else:
            return -1   # phishing

        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')

        registration_length = (expiration_date - datetime.now()).days
        if registration_length > 365:  # more than a year
            return 1   # legitimate
        else:
            return -1  # phishing
    except Exception:
        return -1      # phishing

# Favicon
def favicon(url):
    try:
        # Parse only link tags
        parse_only = SoupStrainer('link', rel=lambda x: x in ['shortcut icon', 'icon'])
        soup = BeautifulSoup(requests.get(url).content, 'html.parser', parse_only=parse_only)

        # Find the favicon link
        favicon_link = soup.find("link", rel="shortcut icon")
        if favicon_link is None:
            favicon_link = soup.find("link", rel="icon")
        if favicon_link is None:
            return 1  # legitimate

        # Parse the favicon URL
        favicon_url = urlparse(favicon_link['href'])

        # Check if the favicon is loaded from the same domain
        if favicon_url.netloc == '':
            return 1  # legitimate
        elif favicon_url.netloc == urlparse(url).netloc:
            return 1  # legitimate
        else:
            return -1  # phishing
    except Exception:
        return -1  # phishing

# port
def non_standard_port(url):
    try:
        # Parse the URL to get the domain and port
        parsed_url = urlparse(url)
        port = parsed_url.port

        # If no port is specified in the URL, assume it's 80 for http and 443 for https
        if port is None:
            if parsed_url.scheme == 'http':
                port = 80
            elif parsed_url.scheme == 'https':
                port = 443

        # List of common ports and their preferred status
        common_ports = {21: 'close', 22: 'close', 23: 'close', 80: 'open', 443: 'open', 445: 'close', 1433: 'close', 1521: 'close', 3306: 'close', 3389: 'close'}

        # Check if the port is in the list of common ports and if it's open
        if port in common_ports and common_ports[port] == 'open':
            return 1  # legitimate
        else:
            return -1  # phishing
    except Exception:
        return -1  # phishing    

# HTTPS_token
def https_token_in_domain(url):
    try:
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Check if "https" is in the domain
        if 'https' in domain:
            return -1  # phishing
        else:
            return 1  # legitimate
    except Exception:
        return -1  # phishing

# Request_URL
def request_url(url):
    try:
        # Parse only img, video, audio, and link tags
        parse_only = SoupStrainer(['img', 'video', 'audio', 'link'])
        soup = BeautifulSoup(requests.get(url).content, 'html.parser', parse_only=parse_only)

        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Find all the external objects in the webpage
        images = soup.find_all('img', src=True)
        videos = soup.find_all('video', src=True)
        audios = soup.find_all('audio', src=True)
        links = soup.find_all('link', href=True)

        # Combine all the external objects into one list
        external_objects = images + videos + audios + links

        # Check if the external objects are loaded from the same domain
        for obj in external_objects:
            obj_url = obj['src'] if 'src' in obj.attrs else obj['href']
            obj_domain = urlparse(obj_url).netloc
            if domain not in obj_domain:
                return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing

# URL_of_Anchor
def url_of_anchor(url):
    try:
         # Parse only a tags
        parse_only = SoupStrainer('a')
        soup = BeautifulSoup(requests.get(url).content, 'html.parser', parse_only=parse_only)

        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Find all the anchors in the webpage
        anchors = soup.find_all('a', href=True)

        # Check if the anchors link to the same domain or don't link to any webpage
        for anchor in anchors:
            anchor_url = anchor['href']
            anchor_domain = urlparse(anchor_url).netloc

            # Check if the anchor doesn't link to any webpage
            if anchor_url.startswith('#') or 'javascript:void(0)' in anchor_url.lower():
                continue

            # Check if the anchor links to a different domain
            if domain not in anchor_domain:
                return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing

# Links_in_tags
def links_in_tags(url):
    try:
        # Parse only meta, script, and link tags
        parse_only = SoupStrainer(['meta', 'script', 'link'])
        soup = BeautifulSoup(requests.get(url).content, 'html.parser', parse_only=parse_only)

        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Find all the <Meta>, <Script>, and <Link> tags in the webpage
        meta_tags = soup.find_all('meta', content=True)
        script_tags = soup.find_all('script', src=True)
        link_tags = soup.find_all('link', href=True)

        # Combine all the tags into one list
        tags = meta_tags + script_tags + link_tags

        # Check if the tags link to the same domain
        for tag in tags:
            tag_url = tag['content'] if 'content' in tag.attrs else (tag['src'] if 'src' in tag.attrs else tag['href'])
            tag_domain = urlparse(tag_url).netloc
            if domain not in tag_domain:
                return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing

# SFH
def sfh(url):
    try:
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Parse only form tags
        parse_only = SoupStrainer('form', action=True)
        soup = BeautifulSoup(requests.get(url).content, 'html.parser', parse_only=parse_only)

        # Find all the form tags in the webpage
        forms = soup.find_all('form', action=True)

        # Check if the SFH is empty, "about:blank", or has a different domain
        for form in forms:
            sfh_url = form['action']
            if sfh_url == "" or sfh_url.lower() == "about:blank":
                return -1  # phishing
            sfh_domain = urlparse(sfh_url).netloc
            if domain not in sfh_domain:
                return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing

# Submitting_to_email
def submitting_to_email(url):
    try:
        # Parse only form tags
        parse_only = SoupStrainer('form', action=True)
        soup = BeautifulSoup(requests.get(url).content, 'html.parser', parse_only=parse_only)

        # Find all the form tags in the webpage
        forms = soup.find_all('form', action=True)

        # Check if the form submits information to an email address
        for form in forms:
            action = form['action']
            if 'mailto:' in action:
                return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing

# Abnormal_URL
import whois
def abnormal_url(url):
    try:
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Get the WHOIS record of the domain
        whois_record = whois.whois(domain)

        # Check if the domain is part of the WHOIS record's identity
        if domain not in whois_record['name']:
            return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing

# Redirect
def website_forwarding(url):
    try:
        response = requests.get(url)
        
        # Count the number of redirects
        if len(response.history) > 4:
            return -1  # phishing
        else:
            return 1  # legitimate
    except Exception:
        return -1  # phishing

# on_mouseover
def on_mouseover(url):
    try:
        # Parse only tags with onmouseover attribute
        parse_only = SoupStrainer(onmouseover=True)
        soup = BeautifulSoup(requests.get(url).content, 'html.parser', parse_only=parse_only)

        # Find all the tags in the webpage that have an onmouseover event
        tags = soup.find_all(onmouseover=True)

        # Check if the onmouseover event changes the status bar
        for tag in tags:
            if 'window.status' in tag['onmouseover']:
                return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing
    
# RightClick
def right_click(url):
    try:
        # Parse only script tags
        parse_only = SoupStrainer('script')
        soup = BeautifulSoup(requests.get(url).content, 'html.parser', parse_only=parse_only)

        # Find all the script tags in the webpage
        scripts = soup.find_all('script')

        # Check if the right-click function is disabled
        for script in scripts:
            if 'event.button==2' in script.text:
                return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing
    
# popUpWidnow
def pop_up_window(url):
    try:
        # Parse only script tags
        parse_only = SoupStrainer('script')
        soup = BeautifulSoup(requests.get(url).content, 'html.parser', parse_only=parse_only)

        # Find all the script tags in the webpage
        scripts = soup.find_all('script')

        # Check if the webpage uses pop-up windows
        for script in scripts:
            if 'window.open(' in script.text:
                return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing

# Iframe
def iframe_redirection(soup):
    try:
        # Parse only iframe tags
        parse_only = SoupStrainer('iframe')
        soup = BeautifulSoup(requests.get(url).content, 'html.parser', parse_only=parse_only)

        # Find all the iframe tags in the webpage
        iframes = soup.find_all('iframe')

        # Check if the webpage uses invisible iframes
        for iframe in iframes:
            if 'frameborder="0"' in str(iframe):
                return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing

# age_of_domain
def age_of_domain(url):
    try:
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Get the WHOIS record of the domain
        whois_record = whois.whois(domain)

        # Check the age of the domain
        creation_date = whois_record.creation_date
        current_date = datetime.now()
        if isinstance(creation_date, list):  # If the creation_date is a list, get the first element
            creation_date = creation_date[0]
        domain_age = (current_date - creation_date).days
        if domain_age < 180:  # 6 months = 180 days
            return -1  # phishing

        return 1  # legitimate
    except Exception:
        return -1  # phishing


# DNSRecord
import socket
def dns_record(url):
    try:
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Check if the domain has a DNS record
        if socket.gethostbyname(domain):
            return 1  # legitimate
        else:
            return -1  # phishing
    except Exception:
        return -1  # phishing

# web_traffic
import json

def website_traffic(url):
    try:
        # Parse the URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Get the Tranco rank of the domain
        response = requests.get(f"https://tranco-list.eu/api/ranks/domain/{domain}")
        data = json.loads(response.text)

        # Check the Tranco rank
        if response.status_code != 200 or not data['ranks']:
            return -1  # phishing
        else:
            latest_rank = data['ranks'][-1]['rank']  # Get the latest rank
            if latest_rank > 100000:
                return 0  # suspicious
            else:
                return 1  # legitimate
    except Exception:
        return -1  # phishing

# Page_Rank
# Google_Index
# Links_pointing_to_page
# Statistical_report


def extract_features(url):
    features_dict = [
        having_ip_address(url),
        url_length(url),
        shortening_service(url),
        having_at_symbol(url),
        double_slash_redirecting(url),
        prefix_suffix(url),
        having_sub_domain(url),
        domain_registration_length(url),
        favicon(url),
        non_standard_port(url),
        https_token_in_domain(url),
        request_url(url),
        url_of_anchor(url),
        links_in_tags(url),
        sfh(url),
        submitting_to_email(url),
        abnormal_url(url),
        website_forwarding(url),
        on_mouseover(url),
        right_click(url),
        pop_up_window(url),
        iframe_redirection(url),
        age_of_domain(url),
        dns_record(url),
        website_traffic(url)
    ]
    return features_dict
