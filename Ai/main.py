import pandas as pd
from metrics import extract_features
from bs4 import BeautifulSoup

urls = pd.read_csv('urls.csv')

print(urls.columns)  # Add this line to check the columns in your DataFrame

benign_url = urls.sample(frac=1)[urls.iloc[:, 1] == "benign"].head(1)
benign_url = benign_url.iloc[0, 0]
if not benign_url.startswith(('http://', 'https://')):
    benign_url = 'http://' + benign_url


phishing_url = urls.sample(frac=1)[urls.iloc[:, 1] == "phishing"].head(1)
phishing_url = phishing_url.iloc[0, 0]
if not phishing_url.startswith(('http://', 'https://')):
    phishing_url = 'http://' + phishing_url


import requests

benign_features = extract_features(benign_url)
phishing_features = extract_features(phishing_url)

# use the saved model to make predictions
import joblib 
model = joblib.load('model.pkl')
print(model.predict([benign_features]))
print(model.predict([phishing_features]))


