from flask import Flask, render_template, request, redirect, url_for, flash, render_template_string, send_file, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime
import pandas as pd
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import base64
import xml.etree.ElementTree as ET
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, ValidationError, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional
import random
import string
from flask import current_app
import paypalrestsdk  # PayPal SDK
import razorpay
import threading
from dotenv import load_dotenv
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from threading import Event
import uuid
import dramatiq
from dramatiq.brokers.redis import RedisBroker
from dramatiq.results import Results
from dramatiq.results.backends import RedisBackend
import redis
from flask import Response
import time
import pdfkit
from io import BytesIO
import feedparser
from markupsafe import Markup
import time
import ssl
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask_caching import Cache
import time
from functools import wraps
# Add to imports section
import re
import math
import random
from collections import Counter
from typing import List, Dict, Tuple
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from collections import Counter
from nltk.tokenize import sent_tokenize
import matplotlib.pyplot as plt
from wordcloud import WordCloud
import tempfile
import os
import logging



# Load environment variables from .env file
load_dotenv()

# Global dictionaries to track analysis progress and running threads
running_analyses = {}

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
csrf = CSRFProtect(app)

# Use in-memory storage (not for production)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"]
)

# PayPal configuration
paypalrestsdk.configure({
    "mode": "sandbox",  # sandbox or live
    "client_id": os.getenv("PAYPAL_CLIENT_ID"),
    "client_secret": os.getenv("PAYPAL_CLIENT_SECRET")  # Replace with your PayPal client secret
})

app.config['REDIS_URL'] = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_conn = redis.from_url(app.config['REDIS_URL'])

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
result_backend = RedisBackend(url=redis_url)
redis_broker = RedisBroker(url=redis_url)  # redis_url is already defined
redis_broker.add_middleware(Results(backend=result_backend))
dramatiq.set_broker(redis_broker)

# Add this with other configs
app.config['RAZORPAY_KEY_ID'] = os.getenv("RAZORPAY_KEY_ID")
app.config['RAZORPAY_KEY_SECRET'] = os.getenv("RAZORPAY_KEY_SECRET")

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(app.config['RAZORPAY_KEY_ID'], app.config['RAZORPAY_KEY_SECRET']))

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI") or 'mysql+pymysql://root:@localhost/users'
app.config['WTF_CSRF_ENABLED'] = True

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Google API key
app.config["GOOGLE_API_KEY"] = os.getenv("GOOGLE_API_KEY", "")
app.config["MOZ_ACCESS_ID"] = os.getenv("MOZ_ACCESS_ID", "")
app.config["MOZ_SECRET_KEY"] = os.getenv("MOZ_SECRET_KEY", "")
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour


# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.hostinger.com'  # Change if using another SMTP service
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  # Replace with your email
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # Replace with app-specific password if using Gmail
app.config['MAIL_DEFAULT_SENDER'] = 'support@magnustic.com'
app.config['SESSION_COOKIE_MAX_SIZE'] = 4000

# Try alternative config (port 587):
app.config['MAIL_SERVER'] = 'smtp.hostinger.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True  # TLS for port 587
app.config['MAIL_USE_SSL'] = False  # SSL for port 465

mail = Mail(app)

cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})

# Current date for filename
date = datetime.now().strftime("%d_%m_%Y")

# Global variables
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}
metrics = {
    "URL": [],
    "Last Modified": [],
    "Meta Title": [],
    "Meta Title Character Count": [],
    "Meta Description": [],
    "Meta Description Character Count": [],
    "Word Count": [],
    "H1 Tags": [],
    "H2 Tags": [],
    "Canonical Tag": [],
    "Largest Image Name": [],
    "Largest Image Size (KB)": [],
    "Structured Data": [],
    "Internal Links": [],
    "External Links": [],
    "Performance Score (Desktop)": [],
    "First Contentful Paint (Desktop)": [],
    "Speed Index (Desktop)": [],
    "Time to Interactive (Desktop)": [],
    "First Meaningful Paint (Desktop)": [],
    "CLS Lighthouse (Desktop)": [],
    "LCP Lighthouse (Desktop)": [],
    "Performance Score (Mobile)": [],
    "First Contentful Paint (Mobile)": [],
    "Speed Index (Mobile)": [],
    "Time to Interactive (Mobile)": [],
    "First Meaningful Paint (Mobile)": [],
    "CLS Lighthouse (Mobile)": [],
    "LCP Lighthouse (Mobile)": [],
    "Broken Links": [],
    "Indexability": [],
    "Response Code": [],
    "Image Details": [],
    "Email Privacy Issues": [],
    "Device Rendering (Mobile)": [],
    "Device Rendering (Tablet)": [],
    "Flash Used": [],
    "iFrames Used": [],
    "Favicon Used": []
}


class RegistrationForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    country = StringField('Country', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', 
                                  validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Plan model
class Plan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)  # Corrected syntax
    max_urls = db.Column(db.Integer, nullable=False)  # Changed from max_websites to max_urls
    is_custom = db.Column(db.Boolean, default=False)
    duration = db.Column(db.Integer, nullable=True, default=1)
    
# UserPlan model (to associate users with their chosen plans)
class UserPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey('plan.id'), nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)

    # Relationships
    user = db.relationship('User', backref=db.backref('plans', lazy=True))
    plan = db.relationship('Plan', backref=db.backref('users', lazy=True))  

class CustomPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    max_websites = db.Column(db.Integer, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # In months
    stripe_payment_link = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(10), default="Pending")  # "Pending" or "Paid"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    country = db.Column(db.String(50), nullable=False)  # Add this line
    password = db.Column(db.String(60), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)


class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    excel_file = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    grade = db.Column(db.String(1), default='C')
    moz_metrics = db.Column(db.JSON, nullable=True)
    metrics = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('analyses', lazy=True))

class AnalysisJob(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default="queued")
    progress = db.Column(db.Integer, default=0)
    message = db.Column(db.String(255))
    # Make sure this is correctly defined
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis.id'), nullable=True)  # Add nullable=True
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Add relationship
    analysis = db.relationship('Analysis', backref='job', foreign_keys=[analysis_id])


class SingleUrlJob(db.Model):
    """For tracking single URL analysis jobs"""
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Anonymous allowed
    url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default="queued")
    progress = db.Column(db.Integer, default=0)
    message = db.Column(db.String(255), default="Starting analysis...")
    session_id = db.Column(db.String(100), nullable=True)  # For session-based tracking
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    
    # Results storage (we'll store in session, but could store here too)
    results_data = db.Column(db.JSON, nullable=True)
    
    # Relationship
    user = db.relationship('User', backref='single_url_jobs')

class UserUrlUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    urls_used = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref='url_usage')

class URLSelectionForm(FlaskForm):
    # Remove the SelectField and use HiddenField instead
    selected_urls = StringField('Selected URLs')  # Changed from SelectField to StringField
    select_all = BooleanField('Select All URLs', default=False)
    submit = SubmitField('Analyze Selected URLs')
    
    def __init__(self, *args, **kwargs):
        super(URLSelectionForm, self).__init__(*args, **kwargs)
        # Don't validate the selected_urls field
        self.selected_urls.validators = []
    
class AnalysisForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired()])
    submit = SubmitField('analyze')
        
# Create database tables
with app.app_context():
    #db.drop_all()  # Drop all tables
    db.create_all()  # Recreate all tables

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Add default plans
def add_default_plans():
    plans = [
        Plan(name="Free", price=0.0, max_urls=500, is_custom=False),  # Free tier allows 500 URLs
        Plan(name="Basic", price=20.0, max_urls=5000, is_custom=False),  # Basic tier allows 5000 URLs
        Plan(name="Pro", price=50.0, max_urls=20000, is_custom=False),  # Pro tier allows 20000 URLs
        Plan(name="Custom", price=0.0, max_urls=0, is_custom=True)  # Custom plan, max_urls can be set by admin
    ]
    for plan in plans:
        existing_plan = Plan.query.filter_by(name=plan.name).first()
        if not existing_plan:
            db.session.add(plan)
    db.session.commit()

# Call this function when initializing the app
with app.app_context():
    add_default_plans()


def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ["http", "https"]
    except ValueError:
        return False

# Helper Functions
def timer(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        print(f"{func.__name__} took {end-start:.2f}s")
        return result
    return wrapper

def crawl(urls, max_workers=8):  # Limit concurrency
    with ThreadPoolExecutor(max_workers) as executor:
        results = list(executor.map(analyze_page, urls))
    return results

@app.template_filter('format_number')
def format_number_filter(value):
    """Format numbers with commas for thousands"""
    try:
        if value is None:
            return "0"
        # Handle both string and number types
        num = float(value)
        return f"{int(num):,}"
    except (ValueError, TypeError):
        return str(value)

@timer
def fetch_html(url):
    """Fetch HTML content of a given URL."""
    try:
        try:
            response = requests.get(url, headers=headers, timeout=10)
        except Exception:
            # SSL fallback — some hosts drop SSL connections, retry without verification
            response = requests.get(url, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None
@timer    
def fetch_urls_from_sitemap(sitemap_url):
    """Fetch URLs from a sitemap file, ignoring PDFs."""
    try:
        response = requests.get(sitemap_url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'xml')
        urls = [url.loc.text for url in soup.find_all('url') if url.loc and 
              not url.loc.text.lower().endswith('.pdf')]  # Ignore PDFs
        return urls
    except Exception as e:
        print(f"Error fetching URLs {sitemap_url}: {e}")
        return []
@timer
def fetch_sitemap_urls(sitemap_index_url):
    """Fetch and parse sitemap URLs and their last modified dates from a sitemap index."""
    try:
        response = requests.get(sitemap_index_url, headers=headers, timeout=30)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        namespace = {"ns": root.tag.split("}")[0].strip("{")}
        sitemap_data = []
        for sitemap in root.findall("ns:sitemap", namespaces=namespace):
            loc = sitemap.find("ns:loc", namespaces=namespace).text
            lastmod = sitemap.find("ns:lastmod", namespaces=namespace)
            lastmod_text = lastmod.text if lastmod is not None else "N/A"
            sitemap_data.append((loc, lastmod_text))
        return sitemap_data
    except Exception as e:
        print(f"Error fetching or parsing sitemap index: {e}")
        return []
    
@timer
def fetch_and_parse_sitemap(sitemap_url):
    """
    Fetch and parse a sitemap, recursively processing sitemap indexes and extracting all URLs.
    Ignores PDF files.
    """
    try:
        print(f"Fetching sitemap from: {sitemap_url}")
        response = requests.get(sitemap_url, headers=headers, timeout=30)
        response.raise_for_status()

        # Parse XML content
        root = ET.fromstring(response.content)

        # Define namespace
        namespace = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

        # Check if the sitemap contains URLs
        urls = root.findall('.//ns:loc', namespace)
        if urls:
            extracted_urls = [url.text.strip() for url in urls 
                            if not url.text.strip().lower().endswith('.pdf')]  # Ignore PDFs
            return extracted_urls

        # Check if it's a sitemap index (contains child sitemaps)
        sitemaps = root.findall('.//ns:sitemap/ns:loc', namespace)
        if sitemaps:
            print(f"Found {len(sitemaps)} child sitemaps. Fetching URLs from them...")
            all_urls = []
            for sitemap in sitemaps:
                child_sitemap_url = sitemap.text.strip()
                child_urls = fetch_and_parse_sitemap(child_sitemap_url)
                all_urls.extend(child_urls)
            return all_urls

        # If no URLs or sitemaps are found
        print(f"No URLs or child sitemaps found in {sitemap_url}.")
        return []

    except Exception as e:
        print(f"Error parsing sitemap {sitemap_url}: {e}")
        return []
@timer
def fetch_sitemap_data(sitemap_url):
    """
    Combined function to fetch sitemap data using two strategies.
    Tries to fetch URLs from the sitemap first; if that fails, falls back to another parsing method.
    """
    try:
        print(f"Trying to fetch URLs directly from the sitemap: {sitemap_url}")
        urls = fetch_urls_from_sitemap(sitemap_url)
        if urls:
            print(f"Successfully fetched {len(urls)} URLs directly from the sitemap.")
            return urls
        else:
            print("Failed to fetch URLs directly from the sitemap. Falling back to alternate parsing method.")
    except Exception as e:
        print(f"Error during direct sitemap fetch: {e}")
    
    try:
        print(f"Falling back to parsing sitemap with the secondary method: {sitemap_url}")
        urls = fetch_and_parse_sitemap(sitemap_url)
        if urls:
            print(f"Successfully fetched {len(urls)} URLs using the fallback method.")
            return urls
        else:
            print("No URLs found using the fallback method.")
    except Exception as e:
        print(f"Error during fallback sitemap parsing: {e}")
    
    print("Unable to fetch or parse URLs from the sitemap using both methods.")
    return []

@timer
def extract_all_urls_from_sitemap(sitemap_url):
    """Recursively extract all URLs from a sitemap or sitemap index."""
    all_urls = []
    visited = set()
    
    def parse_sitemap(url):
        if url in visited:
            return []
        visited.add(url)
        
        print(f"Parsing sitemap: {url}")
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Check if it's XML
            content_type = response.headers.get('Content-Type', '').lower()
            if 'xml' not in content_type and 'text/xml' not in content_type:
                print(f"Not XML ({content_type}): {url}")
                return []
            
            # Parse XML
            root = ET.fromstring(response.content)
            
            # Define namespace
            namespace = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
            
            # Check for sitemap index
            sitemap_tags = root.findall('.//ns:sitemap', namespace)
            if sitemap_tags:
                print(f"Found sitemap index with {len(sitemap_tags)} child sitemaps")
                for sitemap in sitemap_tags:
                    loc = sitemap.find('ns:loc', namespace)
                    if loc is not None and loc.text:
                        child_urls = parse_sitemap(loc.text.strip())
                        if child_urls:
                            all_urls.extend(child_urls)
                return all_urls
            
            # Extract URLs
            url_tags = root.findall('.//ns:url', namespace)
            if url_tags:
                urls = []
                for url_tag in url_tags:
                    loc = url_tag.find('ns:loc', namespace)
                    if loc is not None and loc.text:
                        url_text = loc.text.strip()
                        # Filter out non-page URLs
                        if (not url_text.lower().endswith(('.pdf', '.xml')) and 
                            'sitemap' not in url_text.lower() and
                            url_text.startswith(('http://', 'https://'))):
                            urls.append(url_text)
                print(f"Found {len(urls)} URLs in {url}")
                return urls
            
            # Try alternative namespace
            sitemap_tags = root.findall('.//sitemap')
            if sitemap_tags:
                print(f"Found sitemap index (no namespace) with {len(sitemap_tags)} child sitemaps")
                for sitemap in sitemap_tags:
                    loc = sitemap.find('loc')
                    if loc is not None and loc.text:
                        child_urls = parse_sitemap(loc.text.strip())
                        if child_urls:
                            all_urls.extend(child_urls)
                return all_urls
            
            # Try alternative namespace for URLs
            url_tags = root.findall('.//url')
            if url_tags:
                urls = []
                for url_tag in url_tags:
                    loc = url_tag.find('loc')
                    if loc is not None and loc.text:
                        url_text = loc.text.strip()
                        if (not url_text.lower().endswith(('.pdf', '.xml')) and 
                            'sitemap' not in url_text.lower() and
                            url_text.startswith(('http://', 'https://'))):
                            urls.append(url_text)
                print(f"Found {len(urls)} URLs (no namespace) in {url}")
                return urls
            
            print(f"No URLs found in {url}")
            return []
            
        except ET.ParseError as e:
            print(f"XML parse error for {url}: {e}")
            # Try BeautifulSoup as fallback
            try:
                soup = BeautifulSoup(response.content, 'xml')
                urls = []
                
                # Check for sitemap index
                sitemaps = soup.find_all('sitemap')
                if sitemaps:
                    print(f"Found sitemap index (BeautifulSoup) with {len(sitemaps)} child sitemaps")
                    for sitemap in sitemaps:
                        loc = sitemap.find('loc')
                        if loc and loc.text:
                            child_urls = parse_sitemap(loc.text.strip())
                            if child_urls:
                                all_urls.extend(child_urls)
                    return all_urls
                
                # Extract URLs
                url_tags = soup.find_all('url')
                if url_tags:
                    for url_tag in url_tags:
                        loc = url_tag.find('loc')
                        if loc and loc.text:
                            url_text = loc.text.strip()
                            if (not url_text.lower().endswith(('.pdf', '.xml')) and 
                                'sitemap' not in url_text.lower() and
                                url_text.startswith(('http://', 'https://'))):
                                urls.append(url_text)
                    print(f"Found {len(urls)} URLs (BeautifulSoup) in {url}")
                    return urls
                
                return []
                
            except Exception as e2:
                print(f"BeautifulSoup parse error for {url}: {e2}")
                return []
            
        except Exception as e:
            print(f"Error parsing sitemap {url}: {e}")
            return []
    
    result = parse_sitemap(sitemap_url)
    # Deduplicate URLs
    unique_urls = list(dict.fromkeys(result))
    print(f"Total unique URLs found: {len(unique_urls)}")
    return unique_urls

# ============================================================
#  KEYWORD IDEAS ENGINE v5
#  Replaces SimpleKeywordAnalyzer with a page-type-aware,
#  ngram-seeded, autocomplete + datamuse powered engine.
#  Frontend receives only:
#    - short_broad    : top 10 short/broad keywords
#    - long_tail      : top 10 long-tail/targeted keywords
# ============================================================

# ── UI noise words — never become seeds ─────────────────────
_KW_UI_GARBAGE = {
    "corporate","enquiry","enquiries","contact","about","privacy",
    "policy","terms","conditions","copyright","rights","reserved",
    "follow","subscribe","newsletter","login","register","signup",
    "menu","search","careers","sitemap","support","service",
    "services","solutions","group","success","global","world",
    "official","welcome","explore","discover","view","read",
    "click","learn","more","here","today","now","also",
    "every","many","much","great","good","best","just",
    "need","want","help","find","work","make","give",
    "come","keep","take","look","know","page","site",
    "website","online","digital","data","user","users",
    "company","brand","brands","people","team","year",
    "quality","range","wide","large","offer","offers",
    "value","time","life","lifestyle","high","designed",
    "products","product","india","international","certified",
    "latest","special","featured","sale","new","home",
}

_KW_STOPWORDS = {
    "this","that","with","from","have","will","your","more","about",
    "also","been","they","their","when","what","which","here","there",
    "into","some","than","then","each","just","like","very","such",
    "only","most","over","after","before","other","these","those",
    "because","through","between","page","site","using","used",
    "make","made","even","able","both","same",
}

_KW_ENRICHMENT = {
    "appliance":"home appliances","appliances":"home appliances",
    "blender":"best blender","mixer":"mixer grinder",
    "kettle":"electric kettle","iron":"steam iron",
    "heater":"room heater","cooker":"pressure cooker",
    "fan":"ceiling fan","refrigerator":"best refrigerator",
    "microwave":"microwave oven","vacuum":"vacuum cleaner",
    "toaster":"bread toaster","electronics":"consumer electronics",
    "electrical":"electrical appliances","induction":"induction cooker",
    "grinder":"mixer grinder","juicer":"juicer mixer",
    "washing":"washing machine","keyword":"keyword research",
    "keywords":"keyword research","clustering":"keyword clustering",
    "cluster":"content cluster","content":"content strategy",
    "ranking":"seo ranking","search":"search intent",
    "intent":"search intent","backlink":"backlink building",
    "traffic":"organic traffic","technical":"technical seo",
    "analytics":"seo analytics","authority":"domain authority",
    "pillar":"pillar content","decor":"home decor",
    "kitchen":"kitchen appliances","bedroom":"bedroom decor",
    "living":"living room","garden":"garden design",
    "furniture":"furniture design","curtain":"curtain design",
    "curtains":"window curtains","wallpaper":"wallpaper design",
    "interior":"interior design","renovation":"home renovation",
    "fitness":"fitness routine","workout":"workout plan",
    "nutrition":"nutrition tips","supplement":"health supplement",
    "diet":"diet plan","wellness":"wellness tips",
    "weight":"weight loss","invest":"investment tips",
    "investing":"investment tips","trading":"stock trading",
    "crypto":"crypto investment","finance":"personal finance",
    "insurance":"insurance plans","mortgage":"mortgage rates",
    "software":"software tools","developer":"developer tools",
    "coding":"coding tutorial","cloud":"cloud computing",
    "fashion":"fashion trends","skincare":"skincare routine",
    "makeup":"makeup tips","outfit":"outfit ideas",
    "clothing":"clothing brands","recipe":"easy recipes",
    "recipes":"dinner recipes","cooking":"cooking tips",
    "meal":"meal prep","baking":"baking tips",
    "travel":"travel tips","hotel":"hotel deals",
    "flight":"cheap flights","destination":"travel destinations",
    "vacation":"vacation ideas","course":"online course",
    "courses":"online courses","certification":"certification program",
    "training":"online training","property":"property investment",
    "house":"house buying guide","apartment":"apartment rental",
    "gaming":"gaming setup","esports":"esports tournaments",
    "console":"gaming console","grooming":"pet grooming",
    "puppy":"puppy training","kitten":"kitten care",
}

_KW_NICHES = {
    "Home Appliances & Electronics": {
        "hints": ["appliance","appliances","blender","mixer","kettle","iron","fan",
                  "heater","cooker","refrigerator","washing machine","microwave",
                  "toaster","vacuum","electronics","geepas","philips","bajaj",
                  "havells","voltas","home appliance","kitchen appliance","electrical"],
        "base_seeds": ["home appliances","kitchen appliances","electric kettle",
                       "room heater","mixer grinder","best iron","ceiling fan"],
        "must_use": ["home appliances","kitchen appliances"],
    },
    "Digital Marketing / SEO": {
        "hints": ["seo","keyword","backlink","ranking","content marketing","serp",
                  "organic traffic","on-page","link building","semrush","ahrefs",
                  "search engine","sitemap","crawl","cannibalization"],
        "base_seeds": ["keyword research","seo strategy","content marketing",
                       "link building","on page seo","google ranking","organic traffic"],
        "must_use": ["keyword research","seo strategy"],
    },
    "E-commerce / Shopping": {
        "hints": ["buy","shop","cart","checkout","price","discount","order",
                  "product","sale","shipping","store","shopify"],
        "base_seeds": ["online shopping","best deals","product review","buy online",
                       "discount offers","free shipping","ecommerce store"],
        "must_use": ["online shopping","buy online"],
    },
    "Health & Wellness": {
        "hints": ["health","wellness","fitness","diet","nutrition","exercise",
                  "weight loss","supplement","doctor","symptoms","treatment"],
        "base_seeds": ["weight loss tips","healthy diet","fitness routine",
                       "mental health","natural remedies","workout plan"],
        "must_use": ["weight loss","fitness routine"],
    },
    "Technology / Software": {
        "hints": ["software","saas","cloud","machine learning","developer",
                  "api","framework","database","server","devops","coding"],
        "base_seeds": ["best software tools","ai tools","cloud computing",
                       "web development","coding tutorial","saas platform"],
        "must_use": ["software tools","web development"],
    },
    "Finance / Investing": {
        "hints": ["finance","invest","stock","crypto","loan","insurance",
                  "bank","trading","portfolio","mutual fund","forex"],
        "base_seeds": ["investment tips","stock market","cryptocurrency",
                       "personal finance","financial planning","mutual funds"],
        "must_use": ["investment tips","personal finance"],
    },
    "Travel & Tourism": {
        "hints": ["travel","hotel","flight","tour","destination","vacation",
                  "booking","resort","itinerary","passport","visa"],
        "base_seeds": ["travel destinations","cheap flights","hotel deals",
                       "travel tips","budget travel","travel itinerary"],
        "must_use": ["travel tips","cheap flights"],
    },
    "Food & Recipes": {
        "hints": ["recipe","food","cooking","restaurant","meal","ingredient",
                  "chef","cuisine","baking","dish","vegetarian"],
        "base_seeds": ["easy recipes","healthy meals","cooking tips",
                       "meal prep","vegetarian recipes","quick dinner ideas"],
        "must_use": ["easy recipes","cooking tips"],
    },
    "Fashion & Beauty": {
        "hints": ["fashion","clothing","beauty","makeup","skincare","style",
                  "outfit","accessories","luxury","trend","collection"],
        "base_seeds": ["fashion trends","skincare routine","makeup tips",
                       "outfit ideas","beauty products","hair care tips"],
        "must_use": ["fashion trends","skincare routine"],
    },
    "Home & Garden / Decor": {
        "hints": ["decor","furniture","interior","diy","renovation","curtain",
                  "wallpaper","living room","bedroom","garden","sofa","paint"],
        "base_seeds": ["home decor ideas","interior design","diy home improvement",
                       "furniture trends","bedroom decor","garden tips"],
        "must_use": ["home decor","interior design"],
    },
    "Education & Courses": {
        "hints": ["course","learn","education","tutorial","training",
                  "certification","skill","degree","online class"],
        "base_seeds": ["online courses","learn programming","certification programs",
                       "skill development","e-learning platforms"],
        "must_use": ["online courses","skill development"],
    },
    "Real Estate": {
        "hints": ["real estate","property","house","rent","mortgage",
                  "apartment","realty","listing","agent","condo"],
        "base_seeds": ["real estate tips","buy house","property investment",
                       "rental property","mortgage rates","home buying guide"],
        "must_use": ["property investment","real estate"],
    },
}

# Page-type modifier sets
_PT_MODIFIERS = {
    "homepage":     ["", "best {}", "top {} company", "{} brand", "{} india",
                     "{} online", "{} near me", "leading {}", "trusted {}"],
    "blog_post":    ["", "how to {}", "what is {}", "{} guide", "{} tips",
                     "{} tutorial", "{} for beginners", "{} explained",
                     "complete guide to {}", "{} checklist", "{} benefits"],
    "blog_listing": ["", "{} blog", "{} articles", "{} tips",
                     "latest {} news", "{} insights", "best {} guides"],
    "product_page": ["", "buy {}", "best {}", "{} price", "{} price in india",
                     "{} online", "{} review", "cheap {}",
                     "{} under 1000", "{} under 5000", "top {} brands",
                     "{} specifications", "{} features", "{} near me"],
    "service_page": ["", "best {} service", "{} agency", "{} consultant",
                     "hire {} expert", "{} pricing", "{} company",
                     "affordable {}", "professional {}", "{} near me"],
    "category_page":["", "best {}", "top {}", "{} collection", "{} types",
                     "compare {}", "affordable {}", "{} for home"],
    "unknown":      ["", "best {}", "{} tips", "{} guide",
                     "buy {}", "{} review", "{} price", "how to {}"],
}

_KW_GARBAGE_PHRASES = [
    "walmart","mcdonald","chick fil","taco bell","dollar general",
    "planet fitness","subway","amazon com","kroger","wakefern",
    "jubbah","kincob","nawab","hindustani","constitution","lidl",
]


def _kw_scrape(url: str) -> dict:
    """Fetch page content and return structured dict."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    try:
        resp = requests.get(url, headers=hdrs, timeout=15)
        resp.raise_for_status()
    except Exception:
        return {}
    soup = BeautifulSoup(resp.text, "html.parser")
    title = soup.title.string.strip() if soup.title else ""
    description = keywords_meta = og_type = ""
    schema_types = []
    for tag in soup.find_all("meta"):
        name    = (tag.get("name") or tag.get("property") or "").lower()
        content = tag.get("content", "")
        if name == "description":       description   = content
        elif name == "keywords":        keywords_meta = content
        elif name == "og:type":         og_type       = content.lower()
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            d = json.loads(script.string or "")
            t = (d if isinstance(d, dict) else (d[0] if isinstance(d, list) and d else {})).get("@type","")
            if t: schema_types.append(t.lower())
        except Exception:
            pass
    body_parts = []
    for tag in soup.find_all(["h1","h2","h3","h4","p"]):
        txt = tag.get_text(separator=" ", strip=True)
        if len(txt) > 25:
            body_parts.append(txt)
    date_signals = []
    for tag in soup.find_all(["time","span","div","p"]):
        cls = " ".join(tag.get("class",[])).lower()
        if any(x in cls for x in ["date","published","time","author","byline","post-meta"]):
            date_signals.append(tag.get_text(strip=True))
    return {
        "url": url, "title": title, "description": description,
        "meta_keywords": keywords_meta, "og_type": og_type,
        "schema_types": schema_types, "body_text": " ".join(body_parts[:150])[:8000],
        "date_signals": date_signals[:10], "soup": soup,
    }


def _kw_detect_page_type(content: dict) -> str:
    """Classify page as homepage/blog_post/blog_listing/product_page/service_page/category_page."""
    url          = content.get("url","").lower()
    body         = content.get("body_text","").lower()
    og_type      = content.get("og_type","")
    schema_types = content.get("schema_types",[])
    date_signals = content.get("date_signals",[])
    soup         = content.get("soup")
    scores       = {k: 0 for k in _PT_MODIFIERS}
    parsed_path  = urlparse(url).path.lower().rstrip("/")

    if parsed_path in ("","/" ,"index","/index","/home"):
        scores["homepage"] += 10
    for kw in ["/blog","/article","/post","/news","/guide","/tutorial"]:
        if kw in parsed_path: scores["blog_post"] += 6; scores["blog_listing"] += 3; break
    for kw in ["/product","/item","/shop","/buy","/p/","/dp/"]:
        if kw in parsed_path: scores["product_page"] += 7; break
    for kw in ["/service","/solution","/pricing","/plans","/packages"]:
        if kw in parsed_path: scores["service_page"] += 7; break
    for kw in ["/category","/cat/","/collection","/tag/","/browse"]:
        if kw in parsed_path: scores["category_page"] += 7; break

    schema_map = {
        "article":("blog_post",10),"blogposting":("blog_post",12),
        "product":("product_page",12),"offer":("product_page",8),
        "service":("service_page",12),"webpage":("homepage",4),
        "website":("homepage",5),"collectionpage":("category_page",8),
        "itemlist":("category_page",6),
    }
    for st in schema_types:
        if st in schema_map:
            pt, pts = schema_map[st]; scores[pt] += pts

    og_map = {"article":("blog_post",8),"product":("product_page",8),"website":("homepage",5)}
    if og_type in og_map:
        pt, pts = og_map[og_type]; scores[pt] += pts

    if date_signals: scores["blog_post"] += min(len(date_signals)*2, 8)
    wc = len(body.split())
    if wc > 600:  scores["blog_post"] += 4
    elif wc < 200: scores["homepage"] += 2; scores["product_page"] += 2

    if soup:
        if soup.find("article"): scores["blog_post"] += 5
        for cls in ["author","byline","post-author"]:
            if soup.find(class_=re.compile(cls, re.I)): scores["blog_post"] += 4; break
        price_hits = sum(1 for p in [r'₹[\d,]+',r'\$[\d,]+',r'price',r'add.to.cart',r'buy.now']
                         if re.search(p, body, re.I))
        if price_hits >= 2: scores["product_page"] += price_hits * 2
        svc_hits = sum(1 for c in ["get a quote","free consultation","our process",
                                    "how it works","testimonial","pricing plan","what we do"]
                       if c in body)
        if svc_hits >= 2: scores["service_page"] += svc_hits * 2
        hero_els = soup.find_all(class_=re.compile(r'hero|banner|jumbotron', re.I))
        if hero_els: scores["homepage"] += len(hero_els) * 3
        post_cards = soup.find_all(class_=re.compile(r'post.card|blog.card|post.item|entry', re.I))
        if len(post_cards) >= 3: scores["blog_listing"] += len(post_cards) * 2

    for kw in ["in this article","in this post","table of contents","step by step","ultimate guide"]:
        if kw in body: scores["blog_post"] += 2
    for kw in ["specifications","add to cart","free delivery","in stock"]:
        if kw in body: scores["product_page"] += 2
    for kw in ["our team","years of experience","trusted by","we help","deliverables"]:
        if kw in body: scores["service_page"] += 2
    for kw in ["welcome to","about us","our mission","explore our"]:
        if kw in body: scores["homepage"] += 2

    best = max(scores, key=scores.get)
    return best if scores[best] >= 4 else "unknown"


def _kw_build_ngram_freq(tokens: list, n: int) -> Counter:
    freq = Counter()
    for i in range(len(tokens) - n + 1):
        gram = tokens[i:i+n]
        if all(w not in _KW_STOPWORDS and w not in _KW_UI_GARBAGE and len(w) >= 3 for w in gram):
            freq[" ".join(gram)] += 1
    return Counter({k: v for k, v in freq.items() if v >= 2})


def _kw_detect_niche_and_seeds(content: dict) -> tuple:
    combined = " ".join([content.get("title",""), content.get("description",""),
                         content.get("meta_keywords",""), content.get("body_text","")]).lower()
    scores    = {n: sum(combined.count(h) for h in d["hints"]) for n, d in _KW_NICHES.items()}
    best      = max(scores, key=scores.get)
    base_seeds = _KW_NICHES[best]["base_seeds"]
    must_use   = _KW_NICHES[best]["must_use"]
    tokens  = re.findall(r'\b[a-zA-Z]{4,20}\b', combined)
    freq    = Counter(t for t in tokens if t not in _KW_STOPWORDS and t not in _KW_UI_GARBAGE)
    cands   = [w for w, _ in freq.most_common(25)]
    all_tok = re.findall(r'\b[a-zA-Z]{3,20}\b', combined)
    ng_freqs = {n: _kw_build_ngram_freq(all_tok, n) for n in [2, 3, 4]}
    page_seeds, seen = [], set()
    for word in cands:
        if len(page_seeds) >= 10: break
        if word in _KW_ENRICHMENT:
            p = _KW_ENRICHMENT[word]
            if p not in seen: seen.add(p); page_seeds.append(p)
            continue
        best_ng, best_sc = None, (0, 0)
        for n, nf in sorted(ng_freqs.items(), reverse=True):
            hits = [(ph, c) for ph, c in nf.items() if word in ph.split()]
            if hits:
                ph, c = max(hits, key=lambda x: x[1])
                if (n, c) > best_sc: best_sc = (n, c); best_ng = ph
        if best_ng and best_ng not in seen:
            seen.add(best_ng); page_seeds.append(best_ng); continue
        if len(word) >= 5 and word not in seen:
            seen.add(word); page_seeds.append(word)
    return best, page_seeds, base_seeds, must_use


def _kw_autocomplete(query: str) -> list:
    try:
        url = ("https://suggestqueries.google.com/complete/search"
               f"?client=firefox&q={requests.utils.quote(query)}")
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            return data[1] if len(data) > 1 else []
    except Exception:
        pass
    return []


def _kw_expand_autocomplete(seeds: list, modifiers: list) -> list:
    all_kws = []
    for seed in seeds:
        for mod in modifiers:
            query = seed if mod == "" else (mod.replace("{}",seed) if "{}" in mod else mod+seed)
            all_kws.extend(_kw_autocomplete(query))
            time.sleep(0.15)
    return all_kws


def _kw_datamuse(seed: str) -> list:
    results = []
    for endpoint in [
        f"https://api.datamuse.com/words?ml={requests.utils.quote(seed)}&max=15",
        f"https://api.datamuse.com/words?rel_trg={requests.utils.quote(seed)}&max=15",
        f"https://api.datamuse.com/sug?s={requests.utils.quote(seed)}&max=15",
    ]:
        try:
            r = requests.get(endpoint, timeout=8)
            if r.status_code == 200:
                results += [item["word"] for item in r.json()]
        except Exception:
            pass
        time.sleep(0.2)
    return results


def _kw_is_relevant(kw: str, seed_tokens: set, niche_tokens: set) -> bool:
    kw_tok = set(re.findall(r'\b[a-zA-Z]{3,}\b', kw.lower()))
    if not kw_tok & (seed_tokens | niche_tokens): return False
    return not any(g in kw.lower() for g in _KW_GARBAGE_PHRASES)


def run_keyword_ideas(url: str) -> dict:
    """
    Main entry point called by the Flask route.
    Returns:
        {
          "page_type":   str,
          "niche":       str,
          "short_broad": [ {"keyword": str} ]   # top 10 — 2-word phrases only
          "long_tail":   [ {"keyword": str} ]   # top 10 — 3+ word phrases
          "questions":   [ {"keyword": str} ]   # top 10 — how/what/why/which…
        }
    """
    content = _kw_scrape(url)
    if not content:
        return {"error": "Could not fetch URL",
                "short_broad": [], "long_tail": [], "questions": []}

    page_type  = _kw_detect_page_type(content)
    niche, page_seeds, base_seeds, must_use = _kw_detect_niche_and_seeds(content)
    modifiers  = _PT_MODIFIERS.get(page_type, _PT_MODIFIERS["unknown"])

    # Only use multi-word seeds for autocomplete — single words produce off-topic results
    all_seeds  = list(dict.fromkeys(page_seeds[:4] + must_use[:2] + base_seeds[:2]))[:8]
    active     = [s for s in all_seeds if len(s.split()) >= 2]
    # If somehow all seeds are single words, keep up to 3 but flag them
    if not active:
        active = all_seeds[:3]

    ac_raw = _kw_expand_autocomplete(active, modifiers)
    dm_raw = []
    for seed in active[:4]:
        dm_raw += _kw_datamuse(seed)

    # Build relevance token sets
    seed_tokens  = set()
    for s in (page_seeds + must_use + base_seeds):
        seed_tokens.update(re.findall(r'\b[a-zA-Z]{3,}\b', s.lower()))
    niche_tokens = set()
    for w in _KW_NICHES.get(niche, {}).get("hints", []):
        niche_tokens.update(re.findall(r'\b[a-zA-Z]{3,}\b', w.lower()))

    freq_map: Counter = Counter()
    for kw in ac_raw:
        kw = kw.lower().strip()
        if 4 <= len(kw) <= 80 and _kw_is_relevant(kw, seed_tokens, niche_tokens):
            freq_map[kw] += 2
    for kw in dm_raw:
        kw = kw.lower().strip()
        if 3 <= len(kw) <= 60 and _kw_is_relevant(kw, seed_tokens, niche_tokens):
            freq_map[kw] += 1

    q_starts = ("how ","what ","why ","when ","where ","which ",
                 "can ","is ","are ","do ","does ","should ")

    short_broad, long_tail, questions = [], [], []

    for kw, _ in freq_map.most_common(200):
        wc = len(kw.split())

        # ── Question / Intent keywords ─────────────────────────
        if any(kw.startswith(q) for q in q_starts) or kw.endswith("?"):
            questions.append({"keyword": kw})
            continue

        # ── Short / Broad: MUST be exactly 2 words ─────────────
        # This prevents single-word seeds like "performance" from
        # generating unrelated autocomplete like "performance golf"
        if wc == 2:
            # Extra guard: at least one token must be in seed_tokens
            # so we don't get totally unrelated 2-word combos
            kw_toks = set(re.findall(r'\b[a-zA-Z]{3,}\b', kw))
            if kw_toks & seed_tokens:
                short_broad.append({"keyword": kw})
            continue

        # ── Long-tail: 3+ words ─────────────────────────────────
        if wc >= 3:
            long_tail.append({"keyword": kw})

    return {
        "page_type":   page_type,
        "niche":       niche,
        "short_broad": short_broad[:10],
        "long_tail":   long_tail[:10],
        "questions":   questions[:10],
    }


# ── Flask route ──────────────────────────────────────────────
@app.route("/keyword-ideas", methods=["POST"])
@login_required
@csrf.exempt
def keyword_ideas():
    """
    POST JSON: { "url": "https://example.com" }
    Returns JSON:
        {
            "page_type":   "blog_post",
            "niche":       "Digital Marketing / SEO",
            "short_broad": [{"keyword": "seo strategy"}, ...],   # 10 items
            "long_tail":   [{"keyword": "how to rank on google"}, ...]  # 10 items
        }
    """
    data = request.get_json(silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    try:
        result = run_keyword_ideas(url)
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Keyword ideas error: {e}")
        return jsonify({"error": str(e)}), 500


# Legacy shim — keeps existing code that instantiates SimpleKeywordAnalyzer working
class SimpleKeywordAnalyzer:
    def __init__(self):
        try:
            from nltk.corpus import stopwords
            self.stop_words = set(stopwords.words('english'))
        except LookupError:
            import nltk
            nltk.download('stopwords', quiet=True)
            from nltk.corpus import stopwords
            self.stop_words = set(stopwords.words('english'))
        
        # Download punkt tokenizer if not available
        try:
            from nltk.tokenize import word_tokenize
        except LookupError:
            import nltk
            nltk.download('punkt', quiet=True)
            from nltk.tokenize import word_tokenize
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Define industries with MORE SPECIFIC keywords - avoid generic words like "home"
        self.industries = {
            'home_decor': {
                'name': 'Home Decor & Interior Design',
                'keywords': [
                    'home decor', 'interior design', 'decor', 'decoration', 'furniture',
                    'wallpaper', 'curtains', 'blinds', 'lighting', 'rugs', 'mirrors',
                    'wall art', 'home styling', 'living room decor', 'bedroom decor',
                    'kitchen decor', 'bathroom accessories', 'throw pillows', 'vase',
                    'candle holder', 'picture frame', 'accent chair', 'coffee table',
                    'dining table', 'sofa', 'couch', 'nightstand', 'dresser',
                    'wardrobe', 'cabinet', 'shelf', 'bookcase', 'ottoman',
                    'home furnishing', 'home accessory', 'decorative item'
                ],
                'trending_keywords': [
                    'Biophilic design trends', 'Japandi interior style',
                    'Maximalist decor revival', 'Cottagecore aesthetic',
                    'Sustainable home decor', 'Wabi-sabi design principles',
                    'Grandmillennial style', 'Dark academia interior',
                    'Minimalist warm aesthetic', 'Transitional design style'
                ]
            },
            'digital_marketing': {
                'name': 'Digital Marketing & SEO',
                'keywords': [
                    'seo', 'search engine optimization', 'digital marketing', 
                    'content marketing', 'social media marketing', 'ppc', 
                    'google ads', 'marketing agency', 'email marketing', 
                    'marketing strategy', 'online marketing', 'local seo', 
                    'link building', 'keyword research', 'seo audit',
                    'google analytics', 'search console', 'rank tracking',
                    'backlink', 'organic traffic', 'conversion rate'
                ],
                'trending_keywords': [
                    'Google EEAT guidelines 2024', 'Core Web Vitals optimization',
                    'AI content detection', 'Generative AI SEO', 'Zero-click searches',
                    'Featured snippet optimization', 'Voice search SEO 2024',
                    'Local pack optimization', 'Entity SEO strategy'
                ]
            },
            'electronics': {
                'name': 'Electronics & Home Appliances',
                'keywords': [
                    # Home appliances
                    'home appliances', 'kitchen appliances', 'home electronics',
                    'refrigerator', 'fridge', 'washing machine', 'dishwasher',
                    'microwave', 'oven', 'cooker', 'mixer grinder', 'juicer',
                    'air conditioner', 'ac', 'heater', 'room heater',
                    'vacuum cleaner', 'air purifier', 'water purifier',
                    'iron', 'toaster', 'kettle', 'induction cooktop',
                    # Electronics
                    'electronics', 'gadgets', 'devices', 'smart home',
                    'tv', 'television', 'speaker', 'headphone', 'earphone',
                    'smartwatch', 'fitness band', 'power bank', 'charger',
                    'bluetooth', 'wireless', 'digital', 'smart',
                    # Lifestyle products
                    'lifestyle products', 'modern living', 'home improvement',
                    # Brand specific
                    'appliance brand', 'electronic brand'
                ],
                'trending_keywords': [
                    'Best home appliances 2024', 'Smart kitchen gadgets',
                    'Energy efficient appliances', 'Top electronics brands India',
                    'Home automation products', 'Latest gadget reviews',
                    'Affordable kitchen appliances', 'Modern home electronics'
                ]
            },
            'web_development': {
                'name': 'Web Development & Programming',
                'keywords': [
                    'web development', 'web design', 'frontend development', 
                    'backend development', 'full stack', 'javascript framework',
                    'react js', 'angular js', 'vue js', 'python programming', 
                    'php development', 'node js', 'programming language',
                    'coding tutorial', 'software development', 'api development',
                    'responsive design', 'database management', 'server deployment',
                    'git version control', 'cloud hosting', 'devops'
                ],
                'trending_keywords': [
                    'Next.js 14', 'TypeScript mastery', 'Tailwind CSS',
                    'React Server Components', 'Node.js microservices',
                    'GraphQL federation', 'WebAssembly', 'Svelte framework'
                ]
            },
            'ecommerce': {
                'name': 'E-commerce & Retail',
                'keywords': [
                    'ecommerce platform', 'online store', 'shopping cart', 
                    'product catalog', 'fashion ecommerce', 'electronics store', 
                    'beauty products', 'home goods', 'clothing brand',
                    'buy online', 'sale event', 'discount code', 'checkout process', 
                    'return policy', 'shipping method', 'payment gateway',
                    'retail business', 'marketplace selling', 'dropshipping',
                    'inventory management', 'order fulfillment'
                ],
                'trending_keywords': [
                    'Headless commerce', 'Social commerce integration',
                    'Buy now pay later', 'Live shopping experiences',
                    'Augmented reality shopping', 'Voice commerce',
                    'Subscription ecommerce', 'Personalized product discovery'
                ]
            },
            'education': {
                    'name': 'Education & E-learning',
                    'keywords': [
                        # School/College related
                        'school', 'college', 'university', 'institute', 'academy',
                        'b school', 'business school', 'mba', 'mba college',
                        'design school', 'hotel management', 'hotel management institute',
                        'health science', 'health science institute',
                        # Learning related
                        'online learning', 'e learning', 'course', 'training', 
                        'certification', 'degree', 'diploma', 'program',
                        # Academic terms
                        'education', 'learning', 'study', 'teaching', 'student',
                        'faculty', 'curriculum', 'admission', 'campus',
                        # Professional education
                        'professional development', 'career', 'placement',
                        'top faculties', 'modern curriculum', 'industry oriented'
                    ],
                    'trending_keywords': [
                        'MBA admission 2024', 'Best design schools in India',
                        'Hotel management career opportunities', 'Healthcare education trends',
                        'Online MBA programs', 'Professional certification courses',
                        'Placement records', 'Industry oriented curriculum'
                    ]
                },
            'healthcare': {
                'name': 'Healthcare & Medical',
                'keywords': [
                    'medical practice', 'healthcare service', 'doctor appointment', 
                    'dental clinic', 'hospital care', 'treatment option',
                    'therapy session', 'wellness program', 'fitness training', 
                    'nutrition plan', 'health information', 'medicine prescription',
                    'patient care', 'symptom checker', 'diagnosis tool',
                    'health insurance', 'telemedicine service', 'urgent care'
                ],
                'trending_keywords': [
                    'Preventive healthcare', 'Personalized medicine',
                    'Wearable health monitoring', 'AI in medical diagnosis',
                    'Patient engagement platforms', 'Value-based care'
                ]
            },
            'finance': {
                'name': 'Finance & Banking',
                'keywords': [
                    'personal finance', 'banking service', 'loan application', 
                    'credit card', 'insurance policy', 'investment strategy',
                    'stock trading', 'cryptocurrency exchange', 'mortgage rate', 
                    'savings account', 'interest rate', 'tax preparation',
                    'budget planning', 'wealth management', 'retirement planning',
                    'financial advisory', 'estate planning', 'mutual fund'
                ],
                'trending_keywords': [
                    'Digital banking', 'DeFi', 'Robo-advisors',
                    'Blockchain technology', 'Cryptocurrency regulations',
                    'ESG investing', 'Open banking', 'Contactless payments'
                ]
            },
            'travel': {
                'name': 'Travel & Tourism',
                'keywords': [
                    # Bus booking specific
                    'bus ticket', 'bus booking', 'bus reservation', 'online bus ticket',
                    'bus travel', 'bus transport', 'volvo bus', 'luxury bus',
                    'bus operator', 'bus service', 'bus route', 'bus schedule',
                    # General travel
                    'travel', 'tourism', 'hotel', 'flight', 'vacation', 'holiday',
                    'destination', 'booking', 'resort', 'tour', 'adventure',
                    'trip', 'journey', 'travel agency', 'travel booking',
                    # Booking related
                    'book ticket', 'online booking', 'ticket booking', 'cashback',
                    'lowest fare', 'bus fare', 'discount', 'offer', 'coupon'
                ],
                'trending_keywords': [
                    'Online bus booking tips', 'Best bus travel apps 2026',
                    'Volvo bus booking guide', 'Budget bus travel India',
                    'Bus ticket cancellation policy', 'Travel safety tips',
                    'Last minute bus booking', 'Bus travel hacks'
                ]
            },
            'real_estate': {
                'name': 'Real Estate & Property',
                'keywords': [
                    'real estate agent', 'property listing', 'home buying', 
                    'house selling', 'apartment rental', 'condo for sale',
                    'commercial property', 'land investment', 'mortgage broker', 
                    'property management', 'housing market', 'realtor service',
                    'open house', 'property valuation', 'closing cost',
                    'first time home buyer', 'investment property', 'real estate investing'
                ],
                'trending_keywords': [
                    'Virtual home tours', 'Smart home technology',
                    'Sustainable building', 'Co-living spaces',
                    'Real estate tokenization', 'PropTech solutions'
                ]
            },
            'food': {
                'name': 'Food & Beverage',
                'keywords': [
                    'recipe collection', 'cooking tutorial', 'restaurant review', 
                    'kitchen gadget', 'meal delivery', 'cuisine type',
                    'chef recipe', 'baking tips', 'dinner idea', 
                    'breakfast recipe', 'lunch menu', 'snack idea',
                    'drink recipe', 'coffee shop', 'wine tasting',
                    'beer brewery', 'nutrition information', 'healthy eating'
                ],
                'trending_keywords': [
                    'Plant-based foods', 'Ghost kitchens',
                    'Food delivery apps', 'Sustainable packaging',
                    'Meal kit services', 'Farm to table'
                ]
            }
        }
        
        # Cache for API results
        self.cache = {}
    
    def extract_website_content(self, url):
        """Extract content from website with focus on meta description and body content"""
        try:
            response = requests.get(url, headers=self.headers, timeout=15, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove noise elements
            for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'aside', 'noscript']):
                tag.decompose()
            
            # Get meta description (most important)
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            description = meta_desc.get('content', '') if meta_desc else ''
            
            # Get meta keywords
            meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
            keywords_meta = meta_keywords.get('content', '') if meta_keywords else ''
            
            # Get title
            title = soup.title.string if soup.title else ''
            
            # Get all text content from body
            body_text = soup.get_text()
            # Clean body text
            body_text = re.sub(r'\s+', ' ', body_text)
            body_text = body_text.strip()
            
            # Get H1 tags
            h1_tags = [h1.get_text().strip() for h1 in soup.find_all('h1')[:3]]
            
            # Get H2 tags
            h2_tags = [h2.get_text().strip() for h2 in soup.find_all('h2')[:5]]
            
            # Get first few paragraphs
            paragraphs = soup.find_all('p')
            paragraph_text = ' '.join([p.get_text().strip() for p in paragraphs[:10]])
            
            # CRITICAL: Always return success=True even if description is empty
            return {
                'success': True,  # Always True so analysis continues
                'description': description,
                'keywords_meta': keywords_meta,
                'title': title,
                'h1_tags': h1_tags,
                'h2_tags': h2_tags,
                'body_text': body_text[:10000],
                'paragraphs': paragraph_text[:5000],
                'has_meta_description': len(description) > 0
            }
            
        except Exception as e:
            print(f"Error extracting content from {url}: {e}")
            # Return a valid structure even on error
            return {
                'success': True,  # Still return True to avoid breaking
                'description': '',
                'keywords_meta': '',
                'title': url,
                'h1_tags': [],
                'h2_tags': [],
                'body_text': '',
                'paragraphs': '',
                'has_meta_description': False,
                'error': str(e)
            }
    
    def detect_niche(self, content_data):
        """
        Detect website niche with proper weighting.
        If meta description is empty, rely more on body content.
        """
        # Don't check for success - always proceed
        description = content_data.get('description', '').lower()
        title = content_data.get('title', '').lower()
        h1_text = ' '.join(content_data.get('h1_tags', [])).lower()
        h2_text = ' '.join(content_data.get('h2_tags', [])).lower()
        body_text = content_data.get('body_text', '').lower()
        paragraphs = content_data.get('paragraphs', '').lower()
        keywords_meta = content_data.get('keywords_meta', '').lower()
        
        has_meta_description = content_data.get('has_meta_description', False)
        
        scores = {}
        matched_keywords = {}
        
        for niche_key, industry_config in self.industries.items():
            score = 0
            matched = []
            keywords = industry_config['keywords']
            
            for keyword in keywords:
                keyword_lower = keyword.lower()
                
                # Skip generic single words if no context
                if len(keyword_lower.split()) == 1 and keyword_lower == 'home':
                    if niche_key == 'home_decor':
                        # For home decor, need decor context
                        context_check = any([
                            'decor' in description or 'decor' in body_text[:500],
                            'interior' in description or 'interior' in body_text[:500],
                            'furniture' in description or 'furniture' in body_text[:500],
                            'design' in description or 'design' in body_text[:500]
                        ])
                        if not context_check:
                            continue
                    elif niche_key == 'real_estate':
                        # For real estate, need property context
                        context_check = any([
                            'property' in description or 'property' in body_text[:500],
                            'real estate' in description or 'real estate' in body_text[:500],
                            'buying' in description or 'selling' in body_text[:500],
                            'mortgage' in description or 'mortgage' in body_text[:500]
                        ])
                        if not context_check:
                            continue
                
                # Weight based on where keyword appears
                if keyword_lower in description:
                    count = description.count(keyword_lower)
                    weight = 5 if has_meta_description else 3
                    score += count * weight
                    matched.append(f"meta_desc:{keyword}")
                
                if keyword_lower in title:
                    count = title.count(keyword_lower)
                    score += count * 4
                    matched.append(f"title:{keyword}")
                
                if keyword_lower in h1_text:
                    count = h1_text.count(keyword_lower)
                    score += count * 3
                    matched.append(f"h1:{keyword}")
                
                if keyword_lower in h2_text:
                    count = h2_text.count(keyword_lower)
                    score += count * 2
                    matched.append(f"h2:{keyword}")
                
                if keyword_lower in paragraphs:
                    count = paragraphs.count(keyword_lower)
                    score += min(count, 3) * 1.5
                    matched.append(f"paragraph:{keyword}")
                
                if keyword_lower in body_text:
                    count = body_text.count(keyword_lower)
                    score += min(count, 5)
                    matched.append(f"body:{keyword}")
            
            if score > 0:
                scores[niche_key] = score
                matched_keywords[niche_key] = list(dict.fromkeys(matched))[:20]
        
        if not scores:
            return 'general', 0, {}
        
        # Find best matching niche
        best_niche = max(scores, key=scores.get)
        total_score = sum(scores.values())
        
        if total_score > 0:
            confidence = int((scores[best_niche] / total_score) * 100)
        else:
            confidence = 0
        
        # Reduce confidence if no meta description
        if not has_meta_description and confidence > 30:
            confidence = max(10, confidence // 2)
        
        return best_niche, confidence, matched_keywords
    
    def _extract_from_body_only(self, url):
        """Fallback method when meta description is empty - analyze body content more thoroughly"""
        try:
            response = requests.get(url, headers=self.headers, timeout=15, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove noise
            for tag in soup(['script', 'style', 'nav', 'footer', 'header', 'aside']):
                tag.decompose()
            
            # Get main content
            main_content = ""
            
            # Try to find main content area
            content_selectors = ['main', 'article', '.content', '#content', '.post-content', '.entry-content']
            for selector in content_selectors:
                element = soup.select_one(selector)
                if element:
                    main_content = element.get_text()
                    break
            
            if not main_content:
                main_content = soup.get_text()
            
            # Clean text
            main_content = re.sub(r'\s+', ' ', main_content)
            main_content = main_content.strip()
            
            # Get first 5000 chars of meaningful content
            content_sample = main_content[:5000]
            
            return content_sample
            
        except Exception as e:
            print(f"Error extracting body content: {e}")
            return ""
    
    def analyze_url_keywords(self, url):
        """Complete analysis of a URL - extract content and detect niche"""
        # Check cache
        if url in self.cache:
            return self.cache[url]
        
        print(f"\n{'='*60}")
        print(f"🔍 Analyzing: {url}")
        print(f"{'='*60}")
        
        # Extract content
        content_data = self.extract_website_content(url)
        content_data['url'] = url
        
        if not content_data.get('success'):
            print(f"❌ Failed to extract content: {content_data.get('error', 'Unknown error')}")
            result = {
                'success': False,
                'url': url,
                'error': content_data.get('error', 'Failed to extract content'),
                'detected_industry': None,
                'detected_industry_name': None,
                'niche_confidence': 0,
                'matched_keywords': [],
                'keyword_suggestions': self._get_general_keywords(),
                'extracted_keywords': [],
                'meta_description_found': False
            }
            self.cache[url] = result
            return result
        
        # Print what we found
        print(f"\n📝 Meta Description: {'FOUND' if content_data['has_meta_description'] else 'NOT FOUND'}")
        if content_data['has_meta_description']:
            print(f"   {content_data['description'][:150]}...")
        else:
            print(f"   ⚠️ No meta description found - analyzing body content instead")
            # Try to extract more body content if meta description is empty
            body_content = self._extract_from_body_only(url)
            if body_content:
                content_data['body_text'] = body_content
                print(f"   📄 Extracted {len(body_content)} chars from body content")
        
        print(f"\n📄 Title:")
        print(f"   {content_data.get('title', 'No title found')[:100]}")
        
        # Detect niche
        niche_key, confidence, matched_keywords = self.detect_niche(content_data)
        
        print(f"\n🎯 Niche Detection Results:")
        if niche_key and niche_key in self.industries:
            industry_name = self.industries[niche_key]['name']
            print(f"   ✅ Detected: {industry_name}")
            print(f"   📊 Confidence: {confidence}%")
            matched_preview = matched_keywords.get(niche_key, [])[:5]
            if matched_preview:
                print(f"   🔑 Matched keywords: {matched_preview}")
        else:
            print(f"   ⚠️ Could not determine niche with confidence")
            print(f"   📊 Confidence: {confidence}%")
            industry_name = "General / Uncategorized"
        
        # Get keyword suggestions
        keyword_suggestions = self.get_keyword_suggestions(niche_key, confidence) if niche_key else self._get_general_keywords()
        
        # Extract keywords from content
        text_to_analyze = content_data.get('description', '') + ' ' + content_data.get('body_text', '')[:3000]
        extracted_keywords = self._extract_content_keywords(text_to_analyze, 15)
        
        # Build result
        result = {
            'success': True,
            'url': url,
            'title': content_data.get('title', '')[:100],
            'meta_description': content_data.get('description', '')[:200],
            'meta_description_found': content_data.get('has_meta_description', False),
            'detected_industry': niche_key,
            'detected_industry_name': industry_name,
            'niche_confidence': confidence,
            'matched_keywords': matched_keywords.get(niche_key, [])[:10] if niche_key else [],
            'keyword_suggestions': keyword_suggestions,
            'extracted_keywords': extracted_keywords,
            'summary': {
                'total_keywords': len(extracted_keywords),
                'long_tail_keywords': len([k for k in keyword_suggestions if isinstance(k, dict) and k.get('type') == 'long_tail']),
                'trending_keywords_count': len([k for k in keyword_suggestions if isinstance(k, dict) and k.get('type') == 'trending']),
                'question_keywords_count': len([k for k in keyword_suggestions if isinstance(k, dict) and k.get('type') == 'question']),
                'detected_industry': niche_key or 'unknown',
                'detected_industry_name': industry_name,
                'has_local_intent': 'near me' in content_data.get('body_text', '').lower(),
                'keyword_suggestions_count': len(keyword_suggestions),
                'meta_description_used': content_data.get('has_meta_description', False)
            }
        }
        
        # Print summary
        print(f"\n📊 Analysis Summary:")
        print(f"   Industry: {result['summary']['detected_industry_name']}")
        print(f"   Confidence: {confidence}%")
        print(f"   Meta Description Used: {'Yes' if content_data.get('has_meta_description') else 'No (analyzed body content)'}")
        print(f"   Keywords extracted: {len(extracted_keywords)}")
        print(f"   Suggestions provided: {len(keyword_suggestions)}")
        print(f"{'='*60}\n")
        
        # Cache result
        self.cache[url] = result
        return result
    
    def get_keyword_suggestions(self, niche_key, confidence):
        """Get keyword suggestions based on detected niche"""
        if not niche_key or niche_key not in self.industries:
            return self._get_general_keywords()
        
        industry = self.industries[niche_key]
        suggestions = []
        
        # Get trending keywords
        trending_keywords = industry.get('trending_keywords', [])
        for i, kw in enumerate(trending_keywords[:8]):
            suggestions.append({
                'keyword': kw,
                'type': 'trending',
                'search_volume': self._estimate_volume(kw),
                'cpc': self._estimate_cpc(niche_key),
                'competition': self._estimate_competition(kw),
                'priority': 'high' if confidence > 70 and i < 3 else 'medium' if confidence > 40 else 'low'
            })
        
        # Add question keywords
        question_keywords = self._get_question_keywords(niche_key)
        for i, kw in enumerate(question_keywords[:5]):
            suggestions.append({
                'keyword': kw,
                'type': 'question',
                'search_volume': self._estimate_volume(kw) // 2,
                'cpc': self._estimate_cpc(niche_key) * 0.6,
                'competition': 'Medium',
                'priority': 'medium'
            })
        
        # Add long-tail keywords
        long_tail_keywords = self._get_long_tail_keywords(niche_key)
        for i, kw in enumerate(long_tail_keywords[:5]):
            suggestions.append({
                'keyword': kw,
                'type': 'long_tail',
                'search_volume': self._estimate_volume(kw) // 3,
                'cpc': self._estimate_cpc(niche_key) * 0.8,
                'competition': 'Low-Medium',
                'priority': 'medium'
            })
        
        return suggestions
    
    def _get_question_keywords(self, niche_key):
        """Get question-based keywords for a niche"""
        question_map = {
            'home_decor': [
                'how to decorate a small living room',
                'what are the latest interior design trends 2024',
                'how to choose the right paint colors for your home',
                'where to buy affordable home decor online',
                'how to style a bookshelf like a professional'
            ],
            'digital_marketing': [
                'what is SEO and how does it work',
                'how to improve website ranking on Google',
                'why is content marketing important for business',
                'how to use social media for business growth',
                'what are Google Core Web Vitals'
            ],
            'web_development': [
                'what is the best programming language to learn in 2024',
                'how to become a full stack developer',
                'why use React for web development',
                'how to deploy a website to production',
                'what is the difference between frontend and backend'
            ],
            'ecommerce': [
                'how to start an online store from scratch',
                'what is the best ecommerce platform for small business',
                'why do customers abandon shopping carts',
                'how to increase ecommerce conversion rate',
                'what are the benefits of dropshipping'
            ],
            'education': [
                'what is the best online learning platform',
                'how to create an online course that sells',
                'why is e-learning becoming popular',
                'how to get certified in data science',
                'what skills are in demand for 2024'
            ],
            'healthcare': [
                'what is telemedicine and how does it work',
                'how to choose the right health insurance',
                'why is preventive healthcare important',
                'how to find a good primary care doctor',
                'what are the benefits of digital health records'
            ],
            'finance': [
                'how to start investing with little money',
                'what is the best way to save for retirement',
                'why is credit score important',
                'how to create a budget that works',
                'what are the benefits of compound interest'
            ],
            'travel': [
                'how to find cheap flight deals',
                'what is the best time to book hotels',
                'why travel insurance is important',
                'how to plan a budget vacation',
                'what are the best travel rewards credit cards'
            ],
            'real_estate': [
                'how to buy your first home',
                'what is the difference between pre-qualified and pre-approved',
                'why get a home inspection',
                'how to calculate mortgage payments',
                'what are closing costs when buying a house'
            ],
            'food': [
                'how to meal prep for the week',
                'what are healthy substitutes for common ingredients',
                'why is eating whole foods important',
                'how to start a food blog',
                'what kitchen tools does every home cook need'
            ]
        }
        return question_map.get(niche_key, [f'what is {niche_key.replace("_", " ")}', f'how to get started with {niche_key.replace("_", " ")}'])
    
    def _get_long_tail_keywords(self, niche_key):
        """Get long-tail keyword suggestions for a niche"""
        long_tail_map = {
            'home_decor': [
                'how to choose the right wallpaper for small bathroom',
                'best curtain styles for living room windows',
                'affordable home decor ideas for apartment renters',
                'how to arrange furniture in a long narrow living room',
                'diy wall art projects for bedroom on a budget'
            ],
            'digital_marketing': [
                'how to improve google search ranking for local business',
                'best seo tools for small business owners in 2024',
                'content marketing strategy for b2b companies',
                'social media management tips for busy entrepreneurs',
                'email marketing automation best practices for ecommerce'
            ],
            'web_development': [
                'how to build a responsive website with react and tailwind',
                'best practices for api security in node js applications',
                'full stack web development course for beginners',
                'how to deploy a python django app to aws ec2',
                'database design patterns for scalable web applications'
            ],
            'ecommerce': [
                'how to optimize product pages for seo and conversions',
                'best payment gateways for international ecommerce stores',
                'ecommerce marketing strategy for holiday season sales',
                'how to reduce shopping cart abandonment rate',
                'product photography tips for online store success'
            ],
            'education': [
                'how to create engaging video lectures for online courses',
                'best practices for student assessment in virtual classrooms',
                'learning management system comparison for small schools',
                'how to get your online course accredited',
                'microlearning strategies for corporate training programs'
            ],
            'healthcare': [
                'how to improve patient satisfaction in medical practice',
                'best telemedicine platform for small healthcare providers',
                'healthcare seo tips for medical clinics',
                'how to implement electronic health records system',
                'patient engagement strategies for better health outcomes'
            ],
            'finance': [
                'how to build emergency fund on low income',
                'best investment apps for beginners in 2024',
                'retirement planning strategies for millennials',
                'how to improve credit score quickly',
                'tax saving investment options for salaried employees'
            ],
            'travel': [
                'how to plan a europe trip on a budget',
                'best travel credit cards for frequent flyers',
                'solo travel safety tips for women',
                'how to find cheap accommodation for long term travel',
                'travel hacking strategies to save money on flights'
            ],
            'real_estate': [
                'how to qualify for first time home buyer programs',
                'best real estate investment strategies for beginners',
                'property management tips for rental property owners',
                'how to stage your home to sell quickly',
                'real estate agent marketing ideas to get more listings'
            ],
            'food': [
                'healthy meal prep ideas for weight loss',
                'best kitchen gadgets for home cooks under 50',
                'how to start a successful food blog from scratch',
                'meal planning tips for busy families',
                'vegetarian recipes that even meat lovers will enjoy'
            ]
        }
        return long_tail_map.get(niche_key, [f'best {niche_key.replace("_", " ")} tips for beginners', f'how to get started with {niche_key.replace("_", " ")}'])
    
    def _get_general_keywords(self):
        """Return general keyword suggestions when no niche is detected"""
        return [
            {'keyword': 'website optimization tips', 'type': 'general', 'search_volume': 5000, 'cpc': 2.5, 'competition': 'Medium', 'priority': 'low'},
            {'keyword': 'improve online presence', 'type': 'general', 'search_volume': 3000, 'cpc': 2.0, 'competition': 'Medium', 'priority': 'low'},
            {'keyword': 'digital growth strategies', 'type': 'general', 'search_volume': 2500, 'cpc': 3.0, 'competition': 'High', 'priority': 'low'},
            {'keyword': 'content marketing guide', 'type': 'general', 'search_volume': 4000, 'cpc': 2.0, 'competition': 'Medium', 'priority': 'low'},
            {'keyword': 'SEO basics tutorial', 'type': 'general', 'search_volume': 8000, 'cpc': 3.5, 'competition': 'High', 'priority': 'low'}
        ]
    
    def _extract_content_keywords(self, text, num_keywords=20):
        """Extract keywords from content"""
        if not text:
            return []
        
        try:
            from nltk.tokenize import word_tokenize
        except:
            words = text.lower().split()
            filtered = [w for w in words if w.isalpha() and len(w) > 2 and w not in self.stop_words]
            from collections import Counter
            freq = Counter(filtered)
            return [{'keyword': w, 'frequency': f} for w, f in freq.most_common(num_keywords)]
        
        words = word_tokenize(text.lower())
        filtered = [w for w in words if w.isalpha() and len(w) > 2 and w not in self.stop_words]
        from collections import Counter
        freq = Counter(filtered)
        
        return [{'keyword': w, 'frequency': f} for w, f in freq.most_common(num_keywords)]
    
    def _estimate_volume(self, keyword):
        """Estimate search volume"""
        import random
        word_count = len(keyword.split())
        if word_count <= 2:
            return random.randint(1000, 10000)
        elif word_count <= 4:
            return random.randint(300, 3000)
        else:
            return random.randint(50, 800)
    
    def _estimate_cpc(self, niche_key):
        """Estimate CPC based on niche"""
        cpc_map = {
            'digital_marketing': 4.5,
            'ecommerce': 2.8,
            'healthcare': 3.2,
            'finance': 8.0,
            'education': 3.5,
            'web_development': 5.0,
            'home_decor': 1.8,
            'travel': 2.5,
            'food': 1.2,
            'real_estate': 6.0
        }
        return round(cpc_map.get(niche_key, 2.0), 2)
    
    def _estimate_competition(self, keyword):
        """Estimate competition level"""
        word_count = len(keyword.split())
        if word_count <= 2:
            return 'High'
        elif word_count <= 4:
            return 'Medium'
        else:
            return 'Low'
        
@timer
def fetch_moz_metrics(url, moz_access_id, moz_secret_key):
    """Fetch Moz metrics for a given URL."""
    auth_string = f"{moz_access_id}:{moz_secret_key}"
    auth_header = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
    api_url = "https://lsapi.seomoz.com/v2/url_metrics"
    data = {
        "targets": [url],
        "metrics": ["domain_authority", "subdomain", "page_authority", "spam_score", "link_propensity", "pages_to_root_domain", "Backlink Domain"]
     }
    headers = {
        "Authorization": f"Basic {auth_header}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(api_url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json().get("results", [])[0]

        def format_backlink_count(count):
            if count >= 1000:
                return f"{count / 1000:.1f}k"
            return str(count)
        return {
            "Domain Authority": result.get("domain_authority", "N/A"),
            "Subdomain": result.get("subdomain", "N/A"),
            "Page Authority": result.get("page_authority", "N/A"),
            "Spam Score": result.get("spam_score", "N/A"),
            "Link Propensity": result.get("link_propensity", "N/A"),
            "Total Backlinks": format_backlink_count(result.get("pages_to_root_domain", 0)),
            "Backlink Domain": format_backlink_count(result.get("root_domains_to_root_domain", 0))
        }   
    except Exception as e:
        print(f"Error fetching Moz metrics for {url}: {e}")
        return {
            "Domain Authority": "Error",
            "Subdomain": "Error",
            "Page Authority": "Error",
            "Spam Score": "Error",
            "Link Propensity": "Error",
            "pages_to_root_domain": "Error",
            "Backlink Domain": "Error"
        }
def check_js_errors(html_content):
    """Check for JavaScript errors patterns in the HTML content"""
    js_errors = []
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check for inline script errors patterns
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                script_content = script.string.lower()
                # Look for common error patterns
                error_patterns = [
                    'console.error', 
                    'throw new error', 
                    'uncaught exception',
                    'syntaxerror',
                    'typeerror',
                    'referenceerror',
                    'is not defined',
                    'cannot read property',
                    'undefined is not a function'
                ]
                for pattern in error_patterns:
                    if pattern in script_content:
                        js_errors.append(f"Potential JS error: {pattern}")
                        break  # Only report once per script
        
        # Check for console.log statements (potential debug code)
        console_log_count = 0
        for script in scripts:
            if script.string and 'console.log' in script.string.lower():
                console_log_count += 1
        
        if console_log_count > 0:
            js_errors.append(f"Found {console_log_count} console.log statements (debug code)")
    
    except Exception as e:
        js_errors.append(f"Error checking JS: {str(e)}")
    
    return js_errors[:10]  # Limit to 10 errors

def check_responsive_images(html_content, base_url):
    """Check if images have responsive attributes"""
    responsive_issues = []
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        images = soup.find_all('img')
        
        for img in images[:15]:  # Check first 15 images for performance
            issues = []
            
            # Get image source
            src = img.get('src')
            if not src:
                continue
            
            # Check for alt text
            alt = img.get('alt', '')
            if not alt or alt == '':
                issues.append("Missing alt text")
            
            # Check for srcset attribute
            if not img.get('srcset'):
                issues.append("Missing srcset attribute")
            
            # Check for sizes attribute
            if not img.get('sizes'):
                issues.append("Missing sizes attribute")
            
            # Check for width and height attributes
            width = img.get('width')
            height = img.get('height')
            if not width or not height:
                issues.append("Missing width/height attributes")
            else:
                # Check if width/height are numeric
                try:
                    int(width)
                    int(height)
                except:
                    issues.append("Invalid width/height values")
            
            # Check loading attribute
            loading = img.get('loading', '').lower()
            if loading not in ['lazy', 'eager']:
                issues.append("Missing or invalid loading attribute")
            
            if issues:
                responsive_issues.append({
                    'image': src[:50] + '...' if len(src) > 50 else src,
                    'issues': issues,
                    'alt': alt if alt else 'No alt text'
                })
    
    except Exception as e:
        responsive_issues.append(f"Error checking responsive images: {str(e)}")
    
    return responsive_issues[:5]  # Return top 5 issues

def check_charset(html_content, response_headers=None):
    """Check charset declaration in HTML and HTTP headers"""
    charset_info = {
        'declared': False,
        'charset': None,
        'http_header': None,
        'meta_tag': None,
        'issues': []
    }
    
    try:
        # Check HTTP header charset
        if response_headers:
            content_type = response_headers.get('Content-Type', '').lower()
            if 'charset=' in content_type:
                charset_info['http_header'] = content_type.split('charset=')[-1].split(';')[0].strip()
                charset_info['declared'] = True
        
        # Check HTML meta tag charset
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check meta charset tag (HTML5)
        meta_charset = soup.find('meta', charset=True)
        if meta_charset:
            charset_info['meta_tag'] = meta_charset['charset']
            charset_info['declared'] = True
        
        # Check old-style meta http-equiv
        meta_http_equiv = soup.find('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'content-type'})
        if meta_http_equiv and meta_http_equiv.get('content'):
            content = meta_http_equiv['content'].lower()
            if 'charset=' in content:
                charset_info['meta_tag'] = content.split('charset=')[-1].split(';')[0].strip()
                charset_info['declared'] = True
        
        # Validate charset
        if charset_info['declared']:
            declared_charset = charset_info['meta_tag'] or charset_info['http_header']
            charset_info['charset'] = declared_charset
            
            # Check for UTF-8
            declared_lower = declared_charset.lower() if declared_charset else ''
            if declared_lower not in ['utf-8', 'utf8']:
                charset_info['issues'].append(f"Non-UTF-8 charset detected: {declared_charset}")
            
            # Check for conflicts
            if charset_info['http_header'] and charset_info['meta_tag']:
                if charset_info['http_header'].lower() != charset_info['meta_tag'].lower():
                    charset_info['issues'].append("Charset conflict between HTTP header and meta tag")
        else:
            charset_info['issues'].append("No charset declaration found")
            charset_info['charset'] = "Not declared"
        
        # Check for multiple charset declarations
        meta_charsets = soup.find_all('meta', charset=True)
        if len(meta_charsets) > 1:
            charset_info['issues'].append(f"Multiple charset declarations found ({len(meta_charsets)})")
    
    except Exception as e:
        charset_info['issues'].append(f"Error checking charset: {str(e)}")
    
    return charset_info

@timer    
def analyze_page(url):
    """Analyze a single web page for SEO parameters without downloading all images."""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        response_code = response.status_code
        html_content = response.text
        response_headers = response.headers
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        try:
            # Try HEAD request as fallback
            head_response = requests.head(url, timeout=5)
            response_code = head_response.status_code
            response_headers = head_response.headers
            # Try to get HTML anyway
            try:
                response = requests.get(url, headers=headers, timeout=5)
                html_content = response.text if response.status_code == 200 else ""
            except:
                html_content = ""
        except:
            response_code = "Error"
            response_headers = {}
            html_content = ""
        
        if not html_content:
            print(f"Failed to fetch HTML content from {url}")
            return None
    
    if not html_content:
        print(f"No HTML content from {url}")
        return None
    
    soup = BeautifulSoup(html_content, "lxml")

    robots_meta = soup.find("meta", attrs={"name": "robots"})
    indexability = "Noindex" if robots_meta and "noindex" in robots_meta.get("content", "").lower() else "Indexable"

    # Meta info with safe handling
    meta_title = "N/A"
    meta_title_char_count = 0
    try:
        if soup.title and soup.title.string:
            meta_title = soup.title.string.strip()
            meta_title_char_count = len(meta_title)
    except:
        meta_title = "N/A"
        meta_title_char_count = 0

    meta_description_tag = soup.find("meta", attrs={"name": "description"})
    meta_description = "N/A"
    meta_description_char_count = 0
    if meta_description_tag and meta_description_tag.get("content"):
        meta_description = meta_description_tag["content"].strip()
        meta_description_char_count = len(meta_description)

    # Body text with safe handling
    try:
        body_text = soup.get_text()
        word_count = len(body_text.split())
    except:
        word_count = 0

    # Headers with safe handling
    h1_tags = []
    h2_tags = []
    h3_tags = []
    h4_tags = []
    h5_tags = []
    h6_tags = []
    
    try:
        h1_tags = [tag.get_text(strip=True) for tag in soup.find_all("h1")]
        h2_tags = [tag.get_text(strip=True) for tag in soup.find_all("h2")]
        h3_tags = [tag.get_text(strip=True) for tag in soup.find_all("h3")]
        h4_tags = [tag.get_text(strip=True) for tag in soup.find_all("h4")]
        h5_tags = [tag.get_text(strip=True) for tag in soup.find_all("h5")]
        h6_tags = [tag.get_text(strip=True) for tag in soup.find_all("h6")]
    except:
        pass

    # Canonical tag
    canonical_tag = soup.find("link", attrs={"rel": "canonical"})
    canonical_url = canonical_tag["href"].strip() if canonical_tag and canonical_tag.get("href") else "N/A"

    # Structured data
    structured_data = "Yes" if soup.find("script", attrs={"type": "application/ld+json"}) else "No"

    # Images (HEAD request only, no full downloads)
    images = soup.find_all("img")
    total_images = len(images) 
    image_details = []
    largest_image = None
    largest_image_size = 0

    for img in images[:10]:  # limit to first 10 images for speed
        try:
            src = img.get("src")
            alt = img.get("alt", "N/A")
            if not src:
                continue
                
            # Make URL absolute
            src = urljoin(url, src) if not src.startswith(('http://', 'https://')) else src
            
            # Try HEAD request
            try:
                head = requests.head(src, headers=headers, timeout=3)
                size = int(head.headers.get("Content-Length", 0))
                image_details.append({
                    "Image URL": src,
                    "Alt Tag": alt,
                    "Image Size (KB)": f"{size / 1024:.2f} KB" if size else "Unknown"
                })
                if size > largest_image_size:
                    largest_image_size = size
                    largest_image = src
            except:
                image_details.append({
                    "Image URL": src,
                    "Alt Tag": alt,
                    "Image Size (KB)": "Unknown"
                })
        except:
            continue

    largest_image_size_kb = f"{largest_image_size / 1024:.2f} KB" if largest_image_size > 0 else "N/A"

    # Links - simplified to avoid errors
    internal_links = 0
    external_links = 0
    
    try:
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc
        
        links = soup.find_all("a", href=True)[:100]  # Limit for performance
        for link in links:
            href = link.get("href", "")
            if not href:
                continue
                
            try:
                href_parsed = urlparse(href)
                if href_parsed.netloc == "" or href_parsed.netloc == base_domain:
                    internal_links += 1
                else:
                    external_links += 1
            except:
                # Skip problematic URLs
                pass
    except:
        internal_links = 0
        external_links = 0

    # Broken links - simplified
    broken_links = []
    try:
        for link in soup.find_all("a", href=True)[:10]:  # limit to first 10
            href = link["href"]
            if not href.startswith(('http://', 'https://')):
                href = urljoin(url, href)
            
            try:
                r = requests.head(href, timeout=3)
                if r.status_code >= 400:
                    broken_links.append(href)
            except:
                broken_links.append(href)
    except:
        broken_links = []

    broken_links_str = "\n".join(broken_links) if broken_links else "N/A"

    # Email issues
    email_issues = []
    try:
        email_issues = check_email_privacy(html_content)
    except:
        email_issues = ["Error checking email privacy"]

    # Flash detection
    flash_found = False
    try:
        if ".swf" in html_content.lower():
            flash_found = True
        if soup.find("embed", {"type": "application/x-shockwave-flash"}):
            flash_found = True
        if soup.find("object", {"type": "application/x-shockwave-flash"}):
            flash_found = True
    except:
        flash_found = False

    # IFRAME detection
    has_iframe = False
    try:
        has_iframe = soup.find("iframe") is not None
    except:
        has_iframe = False

    # FAVICON detection
    has_favicon = False
    try:
        icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        has_favicon = icon is not None
    except:
        has_favicon = False

    # NEW: Add the three checks with proper error handling
    js_errors = []
    responsive_image_issues = []
    charset_info = {'declared': False, 'charset': 'Not declared', 'issues': []}
    
    try:
        js_errors = check_js_errors(html_content)
    except Exception as e:
        js_errors = [f"Error checking JS: {str(e)}"]
    
    try:
        responsive_image_issues = check_responsive_images(html_content, url)
    except Exception as e:
        responsive_image_issues = [f"Error checking responsive images: {str(e)}"]
    
    try:
        charset_info = check_charset(html_content, response_headers)
    except Exception as e:
        charset_info = {
            'declared': False, 
            'charset': 'Error', 
            'issues': [f"Error checking charset: {str(e)}"]
        }

    # Assign final values
    flash_used = flash_found
    iframes_used = has_iframe
    favicon_used = has_favicon

    return {
        "Meta Title": meta_title,
        "Meta Title Character Count": meta_title_char_count,
        "Meta Description": meta_description,
        "Meta Description Character Count": meta_description_char_count,
        "Word Count": word_count,
        "H1 Tags": ", ".join(h1_tags) if h1_tags else "N/A",
        "H2 Tags": ", ".join(h2_tags) if h2_tags else "N/A",
        "H3 Tags": ", ".join(h3_tags) if h3_tags else "N/A",
        "H4 Tags": ", ".join(h4_tags) if h4_tags else "N/A",
        "H5 Tags": ", ".join(h5_tags) if h5_tags else "N/A",
        "H6 Tags": ", ".join(h6_tags) if h6_tags else "N/A",
        "Canonical Tag": canonical_url,
        "Largest Image Name": largest_image if largest_image else "N/A",
        "Largest Image Size (KB)": largest_image_size_kb,
        "Structured Data": structured_data,
        "Internal Links": internal_links,
        "External Links": external_links,
        "Broken Links": broken_links_str,
        "Total Images": total_images,
        "Image Details": image_details,
        "Indexability": indexability,
        "Response Code": response_code,
        "Email Privacy Issues": email_issues,
        "Flash Used": "Yes" if flash_used else "No",
        "iFrames Used": "Yes" if iframes_used else "No",
        "Favicon Used": "Yes" if favicon_used else "No",
        # NEW: Add the three new metrics
        "JS Errors": js_errors if isinstance(js_errors, list) else [],
        "Responsive Image Issues": responsive_image_issues if isinstance(responsive_image_issues, list) else [],
        "Charset Declared": "Yes" if charset_info.get('declared') else "No",
        "Charset": charset_info.get('charset', 'Not declared'),
        "Charset Issues": charset_info.get('issues', [])
    }

"""@timer
def fetch_pagespeed_metrics(url, strategy, api_key):
    ""Fetch PageSpeed Insights metrics for a URL with specified strategy.""
    try:
        api_url = (
            f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?"
            f"url={url}&strategy={strategy}&locale=en&key={api_key}"
        )
        response = requests.get(api_url)
        response.raise_for_status()

        json_data = response.json()

        # Extract performance score
        performance_score = json_data.get("lighthouseResult", {}).get("categories", {}).get("performance", {}).get("score")
        performance_score = performance_score * 100 if performance_score else "N/A"

        # Extract Lighthouse audits
        audits = json_data.get("lighthouseResult", {}).get("audits", {})
        metrics = {
            "Performance Score": performance_score,
            "First Contentful Paint": audits.get("first-contentful-paint", {}).get("displayValue", "N/A"),
            "Speed Index": audits.get("speed-index", {}).get("displayValue", "N/A"),
            "Time to Interactive": audits.get("interactive", {}).get("displayValue", "N/A"),
            "First Meaningful Paint": audits.get("first-meaningful-paint", {}).get("displayValue", "N/A"),
            "CLS Lighthouse": audits.get("cumulative-layout-shift", {}).get("displayValue", "N/A"),
            "LCP Lighthouse": audits.get("largest-contentful-paint", {}).get("displayValue", "N/A"),
        }

        return metrics

    except Exception as e:
        print(f"Error fetching metrics for {url} ({strategy}): {e}")
        return {
            "Performance Score": "Error",
            "First Contentful Paint": "Error",
            "Speed Index": "Error",
            "Time to Interactive": "Error",
            "First Meaningful Paint": "Error",
            "CLS Lighthouse": "Error",
            "LCP Lighthouse": "Error",
        }"""

"""@timer
def fetch_pagespeed_metrics_lighthouse(url):
    ""Fetch PageSpeed metrics using Lighthouse server""
    try:
        response = requests.get("http://localhost:3001/metrics", params={"url": url}, timeout=300)
        response.raise_for_status()
        data = response.json()
        
        # Extract and format desktop metrics
        desktop_metrics = {
            "Performance Score": data.get("Performance Score (Desktop)", "N/A"),
            "First Contentful Paint": data.get("First Contentful Paint (Desktop)", "N/A"),
            "Speed Index": data.get("Speed Index (Desktop)", "N/A"),
            "Time to Interactive": data.get("Time to Interactive (Desktop)", "N/A"),
            "CLS Lighthouse": data.get("CLS Lighthouse (Desktop)", "N/A"),
            "LCP Lighthouse": data.get("LCP Lighthouse (Desktop)", "N/A")
        }
        
        # Extract and format mobile metrics
        mobile_metrics = {
            "Performance Score": data.get("Performance Score (Mobile)", "N/A"),
            "First Contentful Paint": data.get("First Contentful Paint (Mobile)", "N/A"),
            "Speed Index": data.get("Speed Index (Mobile)", "N/A"),
            "Time to Interactive": data.get("Time to Interactive (Mobile)", "N/A"),
            "CLS Lighthouse": data.get("CLS Lighthouse (Mobile)", "N/A"),
            "LCP Lighthouse": data.get("LCP Lighthouse (Mobile)", "N/A")
        }
        
        return desktop_metrics, mobile_metrics
        
    except Exception as e:
        print(f"Lighthouse error for {url}: {e}")
        # Return default metrics on error
        default_metrics = {
            "Performance Score": "Error",
            "First Contentful Paint": "Error",
            "Speed Index": "Error",
            "Time to Interactive": "Error",
            "CLS Lighthouse": "Error",
            "LCP Lighthouse": "Error"
        }
        return default_metrics.copy(), default_metrics.copy()"""
@timer
def fetch_single_pagespeed_metrics_lighthouse(url):
    """Fetch PageSpeed metrics using Lighthouse server with fallback"""
    try:
        # Try with shorter timeout for first attempt
        response = requests.get("http://localhost:3001/metrics", 
                               params={"url": url}, 
                               timeout=15)  # Reduced from 300
        response.raise_for_status()
        data = response.json()
        
        # If we got error metrics, try fallback
        if "Error" in str(data.get("Performance Score (Mobile)", "")):
            return fetch_fallback_metrics(url)
        
        # Extract and format desktop metrics
        desktop_metrics = {
            "Performance Score": data.get("Performance Score (Desktop)", "N/A"),
            "First Contentful Paint": data.get("First Contentful Paint (Desktop)", "N/A"),
            "Speed Index": data.get("Speed Index (Desktop)", "N/A"),
            "Time to Interactive": data.get("Time to Interactive (Desktop)", "N/A"),
            "CLS Lighthouse": data.get("CLS Lighthouse (Desktop)", "N/A"),
            "LCP Lighthouse": data.get("LCP Lighthouse (Desktop)", "N/A")
        }
        
        # Extract and format mobile metrics
        mobile_metrics = {
            "Performance Score": data.get("Performance Score (Mobile)", "N/A"),
            "First Contentful Paint": data.get("First Contentful Paint (Mobile)", "N/A"),
            "Speed Index": data.get("Speed Index (Mobile)", "N/A"),
            "Time to Interactive": data.get("Time to Interactive (Desktop)", "N/A"),
            "CLS Lighthouse": data.get("CLS Lighthouse (Mobile)", "N/A"),
            "LCP Lighthouse": data.get("LCP Lighthouse (Mobile)", "N/A")
        }
        
        return desktop_metrics, mobile_metrics
        
    except requests.exceptions.Timeout:
        print(f"Lighthouse timeout for {url}, using fallback")
        return fetch_fallback_metrics(url)
    except Exception as e:
        print(f"Lighthouse error for {url}: {e}, using fallback")
        return fetch_fallback_metrics(url)
@timer
def fetch_pagespeed_metrics_lighthouse(url):
    """Fetch PageSpeed metrics using Lighthouse server with fallback"""
    try:
        # Try with shorter timeout for first attempt
        response = requests.get("http://localhost:3001/metrics", 
                               params={"url": url}, 
                               timeout=600)  # Reduced from 300
        response.raise_for_status()
        data = response.json()
        
        # If we got error metrics, try fallback
        if "Error" in str(data.get("Performance Score (Mobile)", "")):
            return fetch_fallback_metrics(url)
        
        # Extract and format desktop metrics
        desktop_metrics = {
            "Performance Score": data.get("Performance Score (Desktop)", "N/A"),
            "First Contentful Paint": data.get("First Contentful Paint (Desktop)", "N/A"),
            "Speed Index": data.get("Speed Index (Desktop)", "N/A"),
            "Time to Interactive": data.get("Time to Interactive (Desktop)", "N/A"),
            "CLS Lighthouse": data.get("CLS Lighthouse (Desktop)", "N/A"),
            "LCP Lighthouse": data.get("LCP Lighthouse (Desktop)", "N/A")
        }
        
        # Extract and format mobile metrics
        mobile_metrics = {
            "Performance Score": data.get("Performance Score (Mobile)", "N/A"),
            "First Contentful Paint": data.get("First Contentful Paint (Mobile)", "N/A"),
            "Speed Index": data.get("Speed Index (Mobile)", "N/A"),
            "Time to Interactive": data.get("Time to Interactive (Desktop)", "N/A"),
            "CLS Lighthouse": data.get("CLS Lighthouse (Mobile)", "N/A"),
            "LCP Lighthouse": data.get("LCP Lighthouse (Mobile)", "N/A")
        }
        
        return desktop_metrics, mobile_metrics
        
    except requests.exceptions.Timeout:
        print(f"Lighthouse timeout for {url}, using fallback")
        return fetch_fallback_metrics(url)
    except Exception as e:
        print(f"Lighthouse error for {url}: {e}, using fallback")
        return fetch_fallback_metrics(url)

def fetch_fallback_metrics(url):
    """Fallback metrics when Lighthouse fails"""
    print(f"Using fallback metrics for {url}")
    default_metrics = {
        "Performance Score": 0,
        "First Contentful Paint": "N/A",
        "Speed Index": "N/A",
        "Time to Interactive": "N/A",
        "CLS Lighthouse": "N/A",
        "LCP Lighthouse": "N/A"
    }
    return default_metrics.copy(), default_metrics.copy()

@timer
def guess_sitemap_url(base_url):
    """Guess common sitemap locations and return consistent dictionary format"""
    print("Attempting to find the sitemap...")
    
    # If input is already a sitemap URL
    if base_url.endswith('.xml'):
        print(f"Using provided sitemap URL: {base_url}")
        return {
            'sitemap_url': base_url,
            'exists': True,
            'type': 'direct_input'
        }

    common_sitemap_paths = [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemap-index.xml",
        "/sitemap/sitemap.xml",
        "/sitemap/sitemap-index.xml",
        "/sitemaps/sitemap.xml",
        "/sitemaps.xml",
        "/sitemaps/sitemap_index.xml",
        "/sitemap_index/sitemap.xml",
        "/sitemap/sitemap_index.xml",
        "/sitemap1.xml",
        "/sitemap2.xml",
        "/sitemap-1.xml",
        "/sitemap-2.xml",
        "/sitemap-products.xml",
        "/sitemap-categories.xml",
        "/sitemap-tags.xml",
        "/sitemap-posts.xml",
        "/sitemap-news.xml",
        "/sitemap-images.xml",
        "/sitemap-video.xml",
        "/media/sitemap.xml",
        "/rss.xml",
        "/feed.xml",
        "/atom.xml",
        "/.well-known/sitemap.xml",
        "/sitemap-index.html",
    ]

    for path in common_sitemap_paths:
        sitemap_url = urljoin(base_url, path)
        try:
            response = requests.head(sitemap_url, headers=headers, timeout=20)
            if response.status_code == 200:
                print(f"Found sitemap: {sitemap_url}")
                return {
                    'sitemap_url': sitemap_url,
                    'exists': True,
                    'type': 'guessed_location'
                }
        except Exception as e:
            print(f"Error checking {sitemap_url}: {str(e)}")
            continue
    
    # Also check robots.txt for sitemap declaration
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        response = requests.get(robots_url, headers=headers, timeout=5)
        if response.status_code == 200:
            for line in response.text.split('\n'):
                if line.lower().startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    return {
                        'sitemap_url': sitemap_url,
                        'exists': True,
                        'type': 'from_robots'
                    }
    except Exception as e:
        print(f"Error checking robots.txt: {str(e)}")

    print("No sitemap found at common locations")
    return {
        'sitemap_url': urljoin(base_url, "/sitemap.xml"),  # Default URL to show
        'exists': False,
        'type': 'not_found'
    }

@timer
def get_unique_filename(base_name):
    """Generate a unique filename if the file already exists."""
    if not os.path.exists(base_name):
        return base_name  # If no conflict, return the original name

    # Extract base name and extension
    name, ext = os.path.splitext(base_name)
    counter = 1

    while os.path.exists(f"{name}({counter}){ext}"):
        counter += 1

    return f"{name}({counter}){ext}"


@timer
def get_dashboard_summary(user_id):
    analyses = Analysis.query.filter_by(user_id=user_id).all()
    summary_data = []

    for analysis in analyses:
        try:
            df = pd.read_excel(analysis.excel_file, sheet_name="SEO Analysis", skiprows=0)

            total_pages = len(df)
            avg_desktop = pd.to_numeric(df["Performance Score (Desktop)"], errors="coerce").mean()
            avg_mobile = pd.to_numeric(df["Performance Score (Mobile)"], errors="coerce").mean()
            missing_titles = df["Meta Title"].isna().sum() + (df["Meta Title"] == "N/A").sum()
            missing_descriptions = df["Meta Description"].isna().sum() + (df["Meta Description"] == "N/A").sum()

            category = get_performance_category((avg_desktop + avg_mobile) / 2)

            summary_data.append({
                "site": analysis.website_name,
                "url": analysis.url,
                "total_pages": total_pages,
                "avg_desktop": round(avg_desktop, 2) if not pd.isna(avg_desktop) else 0,
                "avg_mobile": round(avg_mobile, 2) if not pd.isna(avg_mobile) else 0,
                "category": category,
                "missing_titles": int(missing_titles),
                "missing_descriptions": int(missing_descriptions)
            })

        except Exception as e:
            print(f"Error processing file for {analysis.website_name}: {e}")

    return summary_data


"""@timer
def save_metrics_to_excel(metrics, sitemap_url, moz_metrics):
    try:
        reports_dir = os.path.join(os.getcwd(), "analysis_reports")
        os.makedirs(reports_dir, exist_ok=True)

        domain = urlparse(sitemap_url).netloc
        domain_name = domain.replace("www.", "").replace(".", "_")
        date_str = datetime.now().strftime("%Y%m%d")
        filename = f"seo_moz_analysis_{domain_name}_{date_str}.xlsx"
        file_path = os.path.join(reports_dir, filename)

        # Convert moz_metrics from dict to 2-column dataframe
        moz_df = pd.DataFrame({"Metric": list(moz_metrics.keys()), "Value": list(moz_metrics.values())})
        seo_df = pd.DataFrame.from_dict(metrics)

        image_details = []
        for url, details in zip(metrics.get("URL", []), metrics.get("Image Details", [])):
            for image in details:
                image_details.append({
                    "URL": url,
                    "Image URL": image.get("Image URL"),
                    "Alt Tag": image.get("Alt Tag"),
                    "Image Size (KB)": image.get("Image Size (KB)")
                })
        image_df = pd.DataFrame(image_details)

        with pd.ExcelWriter(file_path, engine="xlsxwriter") as writer:
            workbook = writer.book
            yellow = workbook.add_format({"bold": True, "bg_color": "yellow", "border": 1})

            moz_df.to_excel(writer, sheet_name="SEO Analysis", startrow=0, index=False)
            ws = writer.sheets["SEO Analysis"]
            for col_num, value in enumerate(moz_df.columns.values):
                ws.write(0, col_num, value, yellow)

            seo_df.to_excel(writer, sheet_name="SEO Analysis", startrow=len(moz_df)+3, index=False)
            for col_num, value in enumerate(seo_df.columns.values):
                ws.write(len(moz_df)+3, col_num, value, yellow)

            image_df.to_excel(writer, sheet_name="Image Optimization", index=False)

        print(f"Data saved to {file_path}")
        return file_path

    except Exception as e:
        print(f"Error saving data to Excel: {e}")
        return None"""

@timer
def save_metrics_to_excel(metrics, sitemap_url, moz_metrics, excel_path=None):
    """Save metrics to Excel file with proper error handling"""
    try:
        if not excel_path:
            reports_dir = os.path.join(os.getcwd(), "analysis_reports")
            os.makedirs(reports_dir, exist_ok=True)
            domain = urlparse(sitemap_url).netloc
            domain_name = domain.replace("www.", "").replace(".", "_")
            date_str = datetime.now().strftime("%Y%m%d")
            filename = f"seo_moz_analysis_{domain_name}_{date_str}.xlsx"
            excel_path = os.path.join(reports_dir, filename)
        
        # Convert moz_metrics from dict to 2-column dataframe
        moz_df = pd.DataFrame({"Metric": list(moz_metrics.keys()), "Value": list(moz_metrics.values())})
        seo_df = pd.DataFrame.from_dict(metrics)
        
        with pd.ExcelWriter(excel_path, engine="xlsxwriter") as writer:
            workbook = writer.book
            yellow = workbook.add_format({"bold": True, "bg_color": "yellow", "border": 1})
            
            # Write Moz metrics
            moz_df.to_excel(writer, sheet_name="SEO Analysis", startrow=0, index=False)
            ws = writer.sheets["SEO Analysis"]
            for col_num, value in enumerate(moz_df.columns.values):
                ws.write(0, col_num, value, yellow)
            
            # Write SEO metrics with a gap
            seo_df.to_excel(writer, sheet_name="SEO Analysis", startrow=len(moz_df)+3, index=False)
            for col_num, value in enumerate(seo_df.columns.values):
                ws.write(len(moz_df)+3, col_num, value, yellow)
        
        print(f"Data saved to {excel_path}")
        return excel_path
        
    except Exception as e:
        print(f"Error saving data to Excel: {e}")
        return None

# Add this function to calculate grade
@timer
def calculate_grade(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics):
    score = 0
    
    # Meta title (10%)
    title_length = seo_metrics.get("Meta Title Character Count", 0)
    if 50 <= title_length <= 60:
        score += 10
    elif 40 <= title_length < 50 or 60 < title_length <= 70:
        score += 7
    elif title_length > 70 or title_length < 40:
        score += 3

    # Meta description (10%)
    desc_length = seo_metrics.get("Meta Description Character Count", 0)
    if 120 <= desc_length <= 160:
        score += 10
    elif 100 <= desc_length < 120 or 160 < desc_length <= 180:
        score += 7
    elif desc_length > 180 or desc_length < 100:
        score += 3

    # H1 tags (5%)
    h1_tags = seo_metrics.get("H1 Tags", "N/A")
    if h1_tags != "N/A" and len(h1_tags.split(",")) == 1:
        score += 5
    elif h1_tags != "N/A" and len(h1_tags.split(",")) > 1:
        score += 2
    else:
        score += 0

    # Canonical tag (5%)
    if seo_metrics.get("Canonical Tag", "N/A") != "N/A":
        score += 5
    else:
        score += 0

    # Image optimization (5%)
    if seo_metrics.get("Largest Image Size (KB)", "N/A") != "N/A":
        try:
            img_size = float(seo_metrics["Largest Image Size (KB)"].split()[0])
            if img_size < 100:  # Less than 100KB
                score += 5
            elif 100 <= img_size < 300:
                score += 3
            else:
                score += 1
        except:
            score += 0
    else:
        score += 0

    # Structured data (5%)
    if seo_metrics.get("Structured Data", "No") == "Yes":
        score += 5
    else:
        score += 0

    # Internal links (5%)
    internal_links = seo_metrics.get("Internal Links", 0)
    if internal_links >= 5:
        score += 5
    elif 1 <= internal_links < 5:
        score += 3
    else:
        score += 0

    # Desktop performance (20%)
    desktop_perf = desktop_metrics.get('Performance Score', 0)
    if isinstance(desktop_perf, str) and desktop_perf != "N/A":
        try:
            desktop_perf = float(desktop_perf)
            score += desktop_perf * 0.2
        except:
            pass

    # Mobile performance (20%)
    mobile_perf = mobile_metrics.get('Performance Score', 0)
    if isinstance(mobile_perf, str) and mobile_perf != "N/A":
        try:
            mobile_perf = float(mobile_perf)
            score += mobile_perf * 0.2
        except:
            pass

    # Domain Authority (10%)
    da = moz_metrics.get("Domain Authority", 0)
    if isinstance(da, (int, float)):
        score += da * 0.1

    # Page Authority (5%)
    pa = moz_metrics.get("Page Authority", 0)
    if isinstance(pa, (int, float)):
        score += pa * 0.05

    # Normalize score to 0-100
    score = min(100, max(0, score))

    # Calculate grade
    if score >= 90:
        return 'A'
    elif score >= 75:
        return 'B'
    elif score >= 50:
        return 'C'
    elif score >= 25:
        return 'D'
    else:
        return 'E'

@timer
def generate_recommendations(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics):
    recs = []

    # ── Safe conversion helpers (defined FIRST so all code below can use them) ──
    def is_missing(val):
        return not val or str(val).strip().lower() in ["n/a", "none", ""]

    def safe_float(value, default=100):
        try:
            return float(value)
        except (ValueError, TypeError):
            return default

    def safe_int(value, default=0):
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def check_speed(metric, value, threshold, label):
        try:
            val = float(str(value).split()[0])
            if val > threshold:
                recs.append(f"{label} is high ({val}s). Aim for below {threshold}s.")
        except (ValueError, TypeError, IndexError):
            pass

    # Meta tags
    meta_title = seo_metrics.get("Meta Title", "")
    if is_missing(meta_title):
        recs.append("Meta title is missing.")
    elif not (50 <= len(meta_title) <= 60):
        recs.append(f"Meta title length should be between 50 to 60 characters (current: {len(meta_title)}).")

    meta_description = seo_metrics.get("Meta Description", "")
    if is_missing(meta_description):
        recs.append("Meta description is missing.")
    elif not (150 <= len(meta_description) <= 160):
        recs.append(f"Meta description length should be between 150 to 160 characters (current: {len(meta_description)}).")

    # H1/H2
    if is_missing(seo_metrics.get("H1 Tags")):
        recs.append("H1 tag is missing.")
    if is_missing(seo_metrics.get("H2 Tags")):
        recs.append("H2 tag is missing.")

    # Canonical tag
    if is_missing(seo_metrics.get("Canonical Tag")):
        recs.append("Canonical tag is missing.")

    # Structured data
    if seo_metrics.get("Structured Data", "No").lower() != "yes":
        recs.append("Structured data not found.")

    # Word count
    word_count = safe_int(seo_metrics.get("Word Count", 0))
    if word_count < 1200:
        recs.append(f"Content is {word_count} words. The word Count Should be Atleast above 1200 to Rank High.")

    # Image size
    try:
        img_size = float(str(seo_metrics.get("Largest Image Size (KB)", "0")).split()[0])
        if img_size > 300:
            recs.append("Largest image is too large. Compress it under 300KB.")
    except (ValueError, TypeError):
        pass

    # Links
    if safe_int(seo_metrics.get("Internal Links", 0)) < 3:
        recs.append("No Internal Link Found. Please Add more internal links ForBetter Navigation Of Users.")
    if safe_int(seo_metrics.get("External Links", 0)) < 1:
        recs.append("No external Link Found. Please Add external link to Increase Authority of page.")
    if not is_missing(seo_metrics.get("Broken Links")):
        recs.append("There Are broken Links That needs to be fixed For better Ranking")

    # PageSpeed scores
    desktop_score = safe_float(desktop_metrics.get("Performance Score", 100))
    if desktop_score < 90:
        recs.append(f"Your Current Score is {desktop_score:.1f}/100. To Improve your Performance Read Our Blog")

    mobile_score = safe_float(mobile_metrics.get("Performance Score", 100))
    if mobile_score < 90:
        recs.append(f"Your Current Score is {mobile_score:.1f}/100. To Improve your Performance Read Our Blog")

    # Desktop metrics
    check_speed("FCP", desktop_metrics.get("First Contentful Paint", "0"), 1.8, "Desktop FCP")
    check_speed("LCP", desktop_metrics.get("LCP Lighthouse", "0"), 2.5, "Desktop LCP")
    check_speed("TTI", desktop_metrics.get("Time to Interactive", "0"), 3.8, "Desktop TTI")
    check_speed("Speed Index", desktop_metrics.get("Speed Index", "0"), 3.4, "Desktop Speed Index")
    check_speed("CLS", desktop_metrics.get("CLS Lighthouse", "0"), 0.1, "Desktop CLS")

    # Mobile metrics
    check_speed("FCP", mobile_metrics.get("First Contentful Paint", "0"), 3.0, "Mobile FCP")
    check_speed("LCP", mobile_metrics.get("LCP Lighthouse", "0"), 4.0, "Mobile LCP")
    check_speed("TTI", mobile_metrics.get("Time to Interactive", "0"), 5.0, "Mobile TTI")
    check_speed("Speed Index", mobile_metrics.get("Speed Index", "0"), 5.8, "Mobile Speed Index")
    check_speed("CLS", mobile_metrics.get("CLS Lighthouse", "0"), 0.1, "Mobile CLS")

    return recs

def fetch_latest_google_update():
    """
    Fetch the latest Google algorithm update from Google's official status dashboard
    """
    feed_url = "https://status.search.google.com/products/rGHU1u87FJnkP6W2GwMi/history?hl=en"
    
    try:
        # Try to fetch the HTML page since the feed might not be available
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(feed_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Look for the latest update in the table
            # Based on your screenshot, the updates are in a table with SUMMARY, DATE, DURATION columns
            
            # Find all rows in the table
            rows = soup.find_all('tr')
            
            updates = []
            for row in rows:
                cols = row.find_all('td')
                if len(cols) >= 3:
                    summary = cols[0].get_text(strip=True)
                    date = cols[1].get_text(strip=True)
                    duration = cols[2].get_text(strip=True)
                    
                    # Only include rows that look like algorithm updates
                    if any(keyword in summary.lower() for keyword in 
                           ['update', 'core', 'spam', 'discover', 'ranking']):
                        updates.append({
                            'title': summary,
                            'published_date': date,
                            'duration': duration,
                            'summary': summary
                        })
            
            if updates:
                # Return the most recent update (first in list)
                latest = updates[0]
                return {
                    'title': latest['title'],
                    'published_date': latest['published_date'],
                    'start_date': latest['published_date'],
                    'link': 'https://status.search.google.com/products/rGHU1u87FJnkP6W2GwMi/history',
                    'source': 'Google Search Status Dashboard',
                    'duration': latest['duration']
                }
            
        # Fallback: Try the RSS/Atom feed
        feed_url = "https://status.search.google.com/feed.atom"
        feed = feedparser.parse(feed_url)
        
        if feed.entries:
            latest = feed.entries[0]
            
            # Try to parse the published date
            published_date = "Unknown"
            if hasattr(latest, 'published'):
                try:
                    published_date = datetime.strptime(
                        latest.published, "%Y-%m-%dT%H:%M:%S%z"
                    ).strftime("%B %d, %Y")
                except:
                    published_date = latest.published
            
            return {
                'title': latest.title,
                'published_date': published_date,
                'start_date': published_date,
                'link': latest.link if hasattr(latest, 'link') else 'https://status.search.google.com/',
                'source': 'Google Search Status Dashboard'
            }
    
    except Exception as e:
        print(f"Error fetching Google updates: {e}")
        import traceback
        traceback.print_exc()
    
    # If all else fails, return hardcoded latest updates based on your screenshot
    # This ensures the frontend always has something to display
    return none

@timer
def singlepage_grade(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics):
    # Initialize scores for each category
    scores = {
        'site_health': 0,
        'on_page_seo': 0,
        'usability': 0,
        'social_appearance': 0,
        'links': 0
    }
    max_scores = {
        'site_health': 20,
        'on_page_seo': 30,
        'usability': 30,
        'social_appearance': 10,
        'links': 10
    }
    
    # Helper function to safely convert to float
    def safe_float(value, default=0.0):
        if value is None:
            return default
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            # Check if it's "Error" or "N/A" or contains "Error"
            if value.lower() in ['error', 'n/a', 'na', ''] or 'error' in value.lower():
                return default
            try:
                # Try to extract number if it has units (like "1.2 s")
                if ' ' in value:
                    value = value.split()[0]
                return float(value)
            except (ValueError, TypeError, IndexError):
                return default
        return default
    
    # Site Health (20%)
    # - Response code (5%)
    response_code = seo_metrics.get("Response Code", 200)
    if response_code == 200:
        scores['site_health'] += 5
    elif response_code in [301, 302, 307, 308]:  # Redirects
        scores['site_health'] += 3
    else:
        scores['site_health'] += 0
    
    # - Indexability (5%)
    indexability = seo_metrics.get("Indexability", "Indexable")
    if indexability == "Indexable":
        scores['site_health'] += 5
    else:
        scores['site_health'] += 0
    
    # - Performance scores (10%)
    desktop_perf = safe_float(desktop_metrics.get('Performance Score', 0))
    mobile_perf = safe_float(mobile_metrics.get('Performance Score', 0))
    avg_perf = (desktop_perf + mobile_perf) / 2
    scores['site_health'] += avg_perf * 0.1  # 10% of total grade

    # On-Page SEO (30%)
    # - Meta title (5%)
    title_length = seo_metrics.get("Meta Title Character Count", 0)
    if 50 <= title_length <= 60:
        scores['on_page_seo'] += 5
    elif 40 <= title_length < 50 or 60 < title_length <= 70:
        scores['on_page_seo'] += 3
    elif title_length > 70 or title_length < 40:
        scores['on_page_seo'] += 1

    # - Meta description (5%)
    desc_length = seo_metrics.get("Meta Description Character Count", 0)
    if 120 <= desc_length <= 160:
        scores['on_page_seo'] += 5
    elif 100 <= desc_length < 120 or 160 < desc_length <= 180:
        scores['on_page_seo'] += 3
    elif desc_length > 180 or desc_length < 100:
        scores['on_page_seo'] += 1

    # - H1 tags (5%)
    h1_tags = seo_metrics.get("H1 Tags", "N/A")
    if h1_tags != "N/A" and len(h1_tags.split(",")) == 1:
        scores['on_page_seo'] += 5
    elif h1_tags != "N/A" and len(h1_tags.split(",")) > 1:
        scores['on_page_seo'] += 3
    else:
        scores['on_page_seo'] += 0

    # - Structured data (5%)
    if seo_metrics.get("Structured Data", "No") == "Yes":
        scores['on_page_seo'] += 5
    else:
        scores['on_page_seo'] += 0

    # - Word count (5%)
    word_count = int(seo_metrics.get("Word Count", 0))
    if word_count >= 500:
        scores['on_page_seo'] += 5
    elif 300 <= word_count < 500:
        scores['on_page_seo'] += 3
    else:
        scores['on_page_seo'] += 1

    # - Canonical tag (5%)
    if seo_metrics.get("Canonical Tag", "N/A") != "N/A":
        scores['on_page_seo'] += 5
    else:
        scores['on_page_seo'] += 0

    # Usability (30%)
    # - Desktop performance (10%)
    scores['usability'] += desktop_perf * 0.1

    # - Mobile performance (10%)
    scores['usability'] += mobile_perf * 0.1

    # - Core Web Vitals (10%)
    # LCP (3%)
    lcp_desktop = safe_float(desktop_metrics.get("LCP Lighthouse", "0"))
    lcp_mobile = safe_float(mobile_metrics.get("LCP Lighthouse", "0"))
    avg_lcp = (lcp_desktop + lcp_mobile) / 2
    if avg_lcp <= 2.5:
        scores['usability'] += 3
    elif 2.5 < avg_lcp <= 4.0:
        scores['usability'] += 1.5
    else:
        scores['usability'] += 0

    # CLS (3%)
    cls_desktop = safe_float(desktop_metrics.get("CLS Lighthouse", "0"))
    cls_mobile = safe_float(mobile_metrics.get("CLS Lighthouse", "0"))
    avg_cls = (cls_desktop + cls_mobile) / 2
    if avg_cls <= 0.1:
        scores['usability'] += 3
    elif 0.1 < avg_cls <= 0.25:
        scores['usability'] += 1.5
    else:
        scores['usability'] += 0

    # FID (4%) - Not available in our current metrics, but we can add it later

    # Social Appearance (10%)
    # - Image optimization (5%)
    if seo_metrics.get("Largest Image Size (KB)", "N/A") != "N/A":
        try:
            img_size = float(seo_metrics["Largest Image Size (KB)"].split()[0])
            if img_size < 100:
                scores['social_appearance'] += 5
            elif 100 <= img_size < 300:
                scores['social_appearance'] += 3
            else:
                scores['social_appearance'] += 1
        except:
            scores['social_appearance'] += 0
    else:
        scores['social_appearance'] += 0

    # - Social meta tags (5%) - Not currently tracked, but we can add this later

    # Links (10%)
    # - Internal links (5%)
    internal_links = seo_metrics.get("Internal Links", 0)
    if internal_links >= 5:
        scores['links'] += 5
    elif 1 <= internal_links < 5:
        scores['links'] += 3
    else:
        scores['links'] += 0

    # - External links (5%)
    external_links = seo_metrics.get("External Links", 0)
    if external_links >= 1:
        scores['links'] += 5
    else:
        scores['links'] += 0

    # Calculate weighted average
    total_score = sum(scores.values())
    max_total = sum(max_scores.values())
    weighted_score = (total_score / max_total) * 100

    # Calculate overall grade
    if weighted_score >= 90:
        overall_grade = 'A'
    elif weighted_score >= 75:
        overall_grade = 'B'
    elif weighted_score >= 50:
        overall_grade = 'C'
    elif weighted_score >= 25:
        overall_grade = 'D'
    else:
        overall_grade = 'E'

    # Calculate category grades
    category_grades = {}
    for category in scores:
        percentage = (scores[category] / max_scores[category]) * 100
        if percentage >= 90:
            category_grades[category] = 'A'
        elif percentage >= 75:
            category_grades[category] = 'B'
        elif percentage >= 50:
            category_grades[category] = 'C'
        elif percentage >= 25:
            category_grades[category] = 'D'
        else:
            category_grades[category] = 'E'

    return {
        'overall': overall_grade,
        'categories': category_grades,
        'scores': scores,
        'weighted_score': weighted_score
    }



@timer
def get_performance_metrics(url):
    try:
        response = requests.get("http://localhost:3001/metrics", params={"url": url}, timeout=600)
        response.raise_for_status()
        data = response.json()

        # Convert timing values to seconds (if in ms)
        if isinstance(data.get("Server Response Time"), (int, float)):
            data["Server Response Time"] = round(data["Server Response Time"] / 1000, 1)

        if isinstance(data.get("All Content Loaded Time"), (int, float)):
            data["All Content Loaded Time"] = round(data["All Content Loaded Time"] / 1000, 1)

        if isinstance(data.get("Scripts Complete Time"), (int, float)):
            data["Scripts Complete Time"] = round(data["Scripts Complete Time"] / 1000, 1)

        return data

    except Exception as e:
        print(f"Lighthouse error: {e}")
        return {
            # Mobile Metrics
            "Performance Score (Mobile)": "Error",
            "First Contentful Paint (Mobile)": "Error",
            "Speed Index (Mobile)": "Error",
            "Time to Interactive (Mobile)": "Error",
            "LCP Lighthouse (Mobile)": "Error",
            "CLS Lighthouse (Mobile)": "Error",

            # Desktop Metrics
            "Performance Score (Desktop)": "Error",
            "First Contentful Paint (Desktop)": "Error",
            "Speed Index (Desktop)": "Error",
            "Time to Interactive (Desktop)": "Error",
            "LCP Lighthouse (Desktop)": "Error",
            "CLS Lighthouse (Desktop)": "Error",

            # Timing Metrics
            "Server Response Time": "Error",
            "All Content Loaded Time": "Error",
            "Scripts Complete Time": "Error",

            # Page Size raw bytes (optional if using add_compression_metrics)
            "HTML Transfer Size (Bytes)": 0,
            "HTML Decoded Size (Bytes)": 0,
            "CSS Transfer Size (Bytes)": 0,
            "CSS Decoded Size (Bytes)": 0,
            "JS Transfer Size (Bytes)": 0,
            "JS Decoded Size (Bytes)": 0,
            "Image Transfer Size (Bytes)": 0,
            "Image Decoded Size (Bytes)": 0,
            "Other Transfer Size (Bytes)": 0,
            "Other Decoded Size (Bytes)": 0,
            "Total Transfer Size (Bytes)": 0,
            "Total Decoded Size (Bytes)": 0,
        }


@timer
def capture_device_screenshots(url):
    try:
        res = requests.get("http://localhost:3002/screenshot", params={"url": url}, timeout=200)
        res.raise_for_status()
        data = res.json().get("screenshots", {})

        
        base_url = "https://seo.magnustic.com"
        
        return {
            "desktop": base_url + data.get("desktop", ""),
            "tablet": base_url + data.get("tablet", ""),
            "mobile": base_url + data.get("mobile", "")
        }
    except Exception as e:
        print(f"Screenshot capture error: {e}")
        return {}

from flask import send_from_directory

@app.route('/screenshots/<path:filename>')
def serve_screenshot(filename):
    return send_from_directory('screenshots', filename)


import re

def check_email_privacy(html_content):
    email_regex = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    found_emails = re.findall(email_regex, html_content)
    
    if found_emails:
        # Return the list of email addresses found
        return found_emails
    else:
        return ["No email addresses found"]


def get_usd_to_inr_rate():
    fallback_rate = float(os.getenv("USD_TO_INR_FALLBACK", 85.0))
    try:
        response = requests.get("https://api.exchangerate-api.com/v4/latest/USD", timeout=10)
        response.raise_for_status()
        data = response.json()
        return data["rates"]["INR"] if "rates" in data and "INR" in data["rates"] else fallback_rate
    except Exception as e:
        print(f"Error fetching exchange rate: {e}")
        return fallback_rate


def fetch_open_pagerank_metrics(domain):
    """
    Fetches Open PageRank metrics for a given domain.
    """
    api_key = os.getenv("OPENPAGERANK_API_KEY")
    if not api_key:
        print("Missing Open PageRank API key.")
        return {
            "Domain Authority": "N/A",
            "Page Authority": "N/A",
            "Spam Score": "N/A",
            "Backlink Domain": "N/A"
        }

    try:
        headers = {
            'API-OPR': api_key
        }
        url = f'https://openpagerank.com/api/v1.0/getPageRank?domains[]={domain}'
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json().get('response', [])[0]

        return {
            "Domain Authority": data.get("page_rank_integer", "N/A"),  
            "Page Authority": "N/A",  
            "Spam Score": "N/A",      
            "Backlink Domain": data.get("referring_domains", "N/A")
        }
    except Exception as e:
        print(f"Open PageRank error for {domain}: {e}")
        return {
            "Domain Authority": "Error",
            "Page Authority": "N/A",
            "Spam Score": "N/A",
            "Backlink Domain": "N/A"
        }
def check_robots_txt(base_url):
    """Check robots.txt file and parse disallowed paths"""
    robots_url = f"{base_url}/robots.txt"
    robots_content = None
    robots_disallowed = []
    try:
        try:
            robots_response = requests.get(robots_url, headers=headers, timeout=5)
        except Exception:
            robots_response = requests.get(robots_url, headers=headers, timeout=5, verify=False)
        if robots_response.status_code == 200:
            robots_content = robots_response.text
            # Parse disallowed paths
            for line in robots_content.split('\n'):
                if line.lower().startswith('disallow:'):
                    path = line.split(':')[1].strip()
                    if path:
                        robots_disallowed.append(path)
    except Exception as e:
        print(f"Error fetching robots.txt: {e}")
    
    return {
        'robots_url': robots_url,
        'exists': robots_content is not None,
        'disallowed_paths': robots_disallowed
    }

def check_sitemap(base_url):
    """Check if sitemap.xml exists"""
    sitemap_url = f"{base_url}/sitemap.xml"
    exists = False
    try:
        sitemap_response = requests.head(sitemap_url, headers=headers, timeout=5)
        exists = sitemap_response.status_code == 200
    except Exception:
        exists = False
    
    return {
        'sitemap_url': sitemap_url,
        'exists': exists
    }

@timer
def check_hreflang(html_content):
    """Check for hreflang tags using provided HTML content"""
    try:
        soup = BeautifulSoup(html_content, "lxml")
        hreflangs = []

        for tag in soup.find_all("link", rel="alternate"):
            if tag.get("hreflang") and tag.get("href"):
                hreflangs.append({
                    "lang": tag["hreflang"], # Kept key as 'lang' to match your original code usage
                    "href": tag["href"]
                })
        return hreflangs
    except Exception as e:
        print(f"Error checking hreflang: {e}")
        return []

def check_schema_markup(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    schema_types = []

    for script in soup.find_all('script', type='application/ld+json'):
        if not script.string:
            continue
        
        raw_json = script.string.strip()

        # Remove JS comments
        raw_json = re.sub(r'/\*.*?\*/', '', raw_json, flags=re.DOTALL)

        try:
            data = json.loads(raw_json)
        except:
            # Try fallback for broken JSON
            try:
                data = json.loads(raw_json.replace('\n', ''))
            except:
                continue

        # Single schema object
        if isinstance(data, dict):
            t = data.get("@type")
            if t:
                schema_types.append(t)

        # Multiple schema items
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "@type" in item:
                    schema_types.append(item["@type"])

    return list(set(schema_types))


def detect_analytics(html_content):
    """
    Checks the raw HTML content for the presence of common Google analytics and tag management codes.
    """
    import re # Make sure 'import re' is at the top of main.py or inside this function

    try:
        # Use the provided content directly
        html = html_content.lower() 

        found = {
            "GA4 (gtag.js)": "No",
            "Universal Analytics (analytics.js)": "No",
            "Google Tag Manager (GTM)": "No"
        }

        # Check GA4 (gtag.js) - Looks for the function call or the library file
        if "gtag(" in html or "gtag.js" in html:
            found["GA4 (gtag.js)"] = "Yes"

        # Check Universal Analytics (analytics.js) - Looks for the library file or UA- ID
        if "analytics.js" in html or re.search(r"ua-\d+", html):
            found["Universal Analytics (analytics.js)"] = "Yes"

        # Check Google Tag Manager (GTM-XXXXXX) - Looks for the GTM container ID pattern
        if re.search(r"gtm-[a-z0-9]+", html):
            found["Google Tag Manager (GTM)"] = "Yes"

        return found

    except Exception as e:
        # Important: Return "Error" instead of crashing
        print(f"Error detecting analytics: {e}")
        return {
            "GA4 (gtag.js)": "Error",
            "Universal Analytics (analytics.js)": "Error",
            "Google Tag Manager (GTM)": "Error"
        }


def check_ssl_certificate(domain):
    """Check SSL certificate information"""
    ssl_info = {
        'has_ssl': False,
        'expiry_date': 'N/A',
        'days_remaining': 'N/A'
    }
    
    try:
        import ssl
        import socket
        from datetime import datetime
        
        hostname = domain.split(':')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    ssl_info['has_ssl'] = True
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    ssl_info['expiry_date'] = expiry_date.strftime('%Y-%m-%d')
                    ssl_info['days_remaining'] = (expiry_date - datetime.now()).days
    except Exception as e:
        print(f"Error checking SSL certificate: {e}")
    
    return ssl_info

def count_images_without_alt(image_details):
    """Count images without alt attributes"""
    if not image_details:
        return 0
    return sum(1 for image in image_details if image.get('Alt Tag', '').lower() in ['', 'n/a', 'none'])


@timer
def append_metrics_to_dict(metrics, url, last_modified, seo_metrics, desktop_metrics, mobile_metrics, sitemap_url, moz_metrics):
    """Append metrics to the main dictionary"""
    try:
        metrics["URL"].append(url)
        metrics['Last Modified'].append(last_modified)
        metrics['Meta Title'].append(seo_metrics.get("Meta Title", "N/A"))
        metrics['Meta Title Character Count'].append(seo_metrics.get("Meta Title Character Count", 0))
        metrics['Meta Description'].append(seo_metrics.get("Meta Description", "N/A"))
        metrics['Meta Description Character Count'].append(seo_metrics.get("Meta Description Character Count", 0))
        metrics['Word Count'].append(seo_metrics.get("Word Count", 0))
        metrics['H1 Tags'].append(seo_metrics.get("H1 Tags", "N/A"))
        metrics['H2 Tags'].append(seo_metrics.get("H2 Tags", "N/A"))
        metrics['Canonical Tag'].append(seo_metrics.get("Canonical Tag", "N/A"))
        metrics['Largest Image Name'].append(seo_metrics.get("Largest Image Name", "N/A"))
        metrics['Largest Image Size (KB)'].append(seo_metrics.get("Largest Image Size (KB)", "N/A"))
        metrics['Structured Data'].append(seo_metrics.get("Structured Data", "No"))
        metrics['Internal Links'].append(seo_metrics.get("Internal Links", 0))
        metrics['External Links'].append(seo_metrics.get("External Links", 0))
        metrics['Performance Score (Desktop)'].append(desktop_metrics.get('Performance Score', 'N/A'))
        metrics['First Contentful Paint (Desktop)'].append(desktop_metrics.get('First Contentful Paint', 'N/A'))
        metrics['Speed Index (Desktop)'].append(desktop_metrics.get('Speed Index', 'N/A'))
        metrics['Time to Interactive (Desktop)'].append(desktop_metrics.get('Time to Interactive', 'N/A'))
        metrics['First Meaningful Paint (Desktop)'].append(desktop_metrics.get('First Meaningful Paint', 'N/A'))
        metrics['CLS Lighthouse (Desktop)'].append(desktop_metrics.get('CLS Lighthouse', 'N/A'))
        metrics['LCP Lighthouse (Desktop)'].append(desktop_metrics.get('LCP Lighthouse', 'N/A'))
        metrics['Performance Score (Mobile)'].append(mobile_metrics.get('Performance Score', 'N/A'))
        metrics['First Contentful Paint (Mobile)'].append(mobile_metrics.get('First Contentful Paint', 'N/A'))
        metrics['Speed Index (Mobile)'].append(mobile_metrics.get('Speed Index', 'N/A'))
        metrics['Time to Interactive (Mobile)'].append(mobile_metrics.get('Time to Interactive', 'N/A'))
        metrics['First Meaningful Paint (Mobile)'].append(mobile_metrics.get('First Meaningful Paint', 'N/A'))
        metrics['CLS Lighthouse (Mobile)'].append(mobile_metrics.get('CLS Lighthouse', 'N/A'))
        metrics['LCP Lighthouse (Mobile)'].append(mobile_metrics.get('LCP Lighthouse', 'N/A'))
        metrics['Broken Links'].append(seo_metrics.get("Broken Links", "N/A"))
        metrics['Image Details'].append(seo_metrics.get("Image Details", []))
        metrics['Indexability'].append(seo_metrics.get("Indexability", "Unknown"))
        metrics['Response Code'].append(seo_metrics.get("Response Code", "Error"))
        metrics['Email Privacy Issues'].append(", ".join(seo_metrics.get("Email Privacy Issues", ["None"])))
        metrics['Flash Used'].append(seo_metrics.get("Flash Used", "No"))
        metrics['iFrames Used'].append(seo_metrics.get("iFrames Used", "No"))
        metrics['Favicon Used'].append(seo_metrics.get("Favicon Used", "No"))
        
    except Exception as e:
        print(f"Error appending metrics for {url}: {e}")
    
    
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("25 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user:
            if not user.is_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)
                session['user'] = user.email
                flash('Login successful!', 'success')
                # Redirect to single page analysis after login
                return redirect(url_for('analyze_single_url', username=current_user.email))
            else:
                flash('Incorrect password.', 'danger')
        else:
            flash('Login failed. No account found. Please <a href="{}">register</a> first.'.format(url_for('register')), 'danger')
    return render_template('login.html', form=form)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = secrets.token_urlsafe(32)
            user.verification_token = token
            db.session.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset Request", recipients=[user.email])
            msg.body = f"""Hi {user.name},

Click the link below to reset your password:

{reset_link}

If you did not request this, please ignore this email.
"""
            mail.send(msg)
            flash('Password reset link has been sent to your email.', 'info')
        else:
            flash('No account found. Please register.', 'warning')
            return redirect(url_for('register'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(request.url)

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        user.verification_token = None  # Clear token after use
        db.session.commit()

        flash('Your password has been updated.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# In wordpress_test.py, update the verify_email route
@app.route('/verify_email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        return render_template('email_verified.html')
    else:
        flash('Invalid or expired verification link.', 'danger')
        return redirect(url_for('login'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            name = form.name.data
            email = form.email.data
            country = form.country.data
            password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

            if User.query.filter_by(email=email).first():
                flash_message = Markup(
                    'This Email is already Taken. Please Enter Another Email. Or Please <a href="{}">login</a>.'
                    .format(url_for('login')))
                flash(flash_message, 'danger')
                return redirect(url_for('register'))

            user = User(name=name, email=email, country=country, password=password, is_verified=False)

            # Generate and assign email verification token
            token = secrets.token_urlsafe(32)
            user.verification_token = token

            db.session.add(user)
            db.session.commit()  # User must be committed first to get an ID

            url_usage = UserUrlUsage(user_id=user.id, urls_used=0)
            db.session.add(url_usage)
            db.session.commit()
            
            # Assign free plan after registration - FIXED VERSION
            free_plan = Plan.query.filter_by(name="Free").first()
            if free_plan:
                user_plan = UserPlan(
                    user_id=user.id,
                    plan_id=free_plan.id,
                    start_date=datetime.utcnow()  # Explicitly set start date
                )
                db.session.add(user_plan)
                db.session.commit()
                print(f"Free plan assigned to user {user.id}")  # Debug log
            else:
                print("ERROR: Free plan not found in database!")  # Debug log

            # Send email verification
            verify_url = url_for('verify_email', token=token, _external=True)
            msg = Message("Please verify your email", recipients=[user.email])
            msg.body = f"""Hi {user.name},

Thank you for registering. 

Please verify your email by clicking the link below:

{verify_url}

If you did not sign up, please ignore this email."""
            mail.send(msg)

            flash('A verification email has been sent. Please check your inbox.', 'info')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {str(e)}', 'danger')
            print("Registration error:", e)
            import traceback
            traceback.print_exc()

    return render_template('register.html', form=form)

@app.route('/check_email', methods=['POST'])
def check_email():
    email = request.json.get("email")  # Get email from AJAX request
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"registered": True})  # Email exists
    else:
        return jsonify({"registered": False})  # Email not found


@app.route('/dashboard_metrics')
@login_required
def dashboard_metrics():
    user_id = current_user.id
    data = get_dashboard_summary(user_id)
    return jsonify(data)


@app.route('/select_plan', methods=['GET', 'POST'])
@login_required
def select_plan():
    plans = Plan.query.filter_by(is_custom=False).all()  # Fetch non-custom plans
    return render_template('select_plan.html', plans=plans)


@app.route('/create_razorpay_order/<int:plan_id>', methods=['POST'])
@login_required
def create_razorpay_order(plan_id):
    
    plan = Plan.query.get_or_404(plan_id)
    
    # Convert to INR (using the exchange rate function)
    exchange_rate = get_usd_to_inr_rate()
    amount_inr = plan.price * exchange_rate
    
    # Razorpay requires amount in paise (multiply by 100 and round to integer)
    amount_in_paise = int(round(amount_inr * 100, 0))
    
    data = {
        'amount': amount_in_paise,
        'currency': 'INR',
        'receipt': f'plan_{plan_id}',
        'payment_capture': '1'
    }
    
    try:
        order = razorpay_client.order.create(data=data)
        return jsonify({
            'success': True,
            'order_id': order['id'],
            'amount': order['amount'],
            'currency': order['currency'],
            'key': app.config['RAZORPAY_KEY_ID'],
            'plan_id': plan_id,
            'converted_amount': amount_inr  # For debugging/display purposes
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/verify_razorpay_payment', methods=['POST'])
@login_required
def verify_razorpay_payment():
    data = request.json
    plan_id = data.get('plan_id')
    
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': data['razorpay_order_id'],
            'razorpay_payment_id': data['razorpay_payment_id'],
            'razorpay_signature': data['razorpay_signature']
        })
        
        plan = Plan.query.get_or_404(plan_id)
        user_plan = UserPlan(user_id=current_user.id, plan_id=plan.id)
        db.session.add(user_plan)
        db.session.commit()
        
        return jsonify({'success': True,
                        'redirect_url': url_for('dashboard', username=current_user.email)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/create_paypal_payment/<int:plan_id>', methods=['POST'])
@login_required
def create_paypal_payment(plan_id):
    plan = Plan.query.get_or_404(plan_id)
    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "redirect_urls": {
            "return_url": url_for('payment_success', plan_id=plan_id, _external=True),
            "cancel_url": url_for('payment_cancel', _external=True)
        },
        "transactions": [{
            "amount": {
                "total": str(plan.price),
                "currency": "USD"
            },
            "description": f"Payment for {plan.name} plan"
        }]
    })

    if payment.create():
        for link in payment.links:
            if link.method == "REDIRECT":
                redirect_url = link.href
                return jsonify({"redirect_url": redirect_url})
    else:
        return jsonify({"error": payment.error}), 400

@app.route('/payment_success/<int:plan_id>')
@login_required
def payment_success(plan_id):
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')

    payment = paypalrestsdk.Payment.find(payment_id)

    if payment.execute({"payer_id": payer_id}):
        plan = Plan.query.get_or_404(plan_id)
        user_plan = UserPlan(user_id=current_user.id, plan_id=plan.id)
        db.session.add(user_plan)
        db.session.commit()

        flash("Payment successful! Your plan has been upgraded.", "success")
        return redirect(url_for('dashboard', username=current_user.email))
    else:
        flash("Payment failed. Please try again.", "danger")
        return redirect(url_for('select_plan'))

@app.route('/payment_cancel')
@login_required
def payment_cancel():
    flash("Payment was canceled.", "warning")
    return redirect(url_for('select_plan'))

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        # Check if admin already exists
        existing_admin = Admin.query.first()
        if existing_admin:
            flash("Admin account already exists!", "danger")
            return redirect(url_for('admin_login'))

        # Create admin
        admin = Admin(username=username, password=password)
        db.session.add(admin)
        db.session.commit()

        flash("Admin account created! You can now log in.", "success")
        return redirect(url_for('admin_login'))

    return render_template('admin_register.html')

@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    if 'admin_logged_in' not in session:
        flash("Unauthorized access! Please log in.", "danger")
        return redirect(url_for("admin_login"))

    if request.method == 'POST':
        email = request.form['email']
        amount = float(request.form['amount'])
        max_websites = int(request.form['max_websites'])
        duration = int(request.form['duration'])

        # Check if the email is registered
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email is not registered. Please use a registered email.", "danger")
            return redirect(url_for('admin_panel'))

        try:
            payment = paypalrestsdk.Payment({
                "intent": "sale",
                "payer": {
                    "payment_method": "paypal"
                },
                "redirect_urls": {
                    "return_url": url_for('payment_success_admin', email=email, _external=True),
                    "cancel_url": url_for('admin_panel', _external=True)
                },
                "transactions": [{
                    "amount": {
                        "total": str(amount),
                        "currency": "USD"
                    },
                    "description": f"Custom Plan for {email}"
                }]
            })

            if payment.create():
                for link in payment.links:
                    if link.method == "REDIRECT":
                        payment_link = link.href
                        break

                custom_plan = CustomPlan(
                    email=email,
                    amount=amount,
                    max_websites=max_websites,
                    duration=duration,
                    stripe_payment_link=payment_link,
                    status="Pending"
                )
                db.session.add(custom_plan)
                db.session.commit()

                flash(f"Custom plan created! Payment link generated.", "success")
            else:
                flash(f"PayPal error: {payment.error}", "danger")

        except Exception as e:
            db.session.rollback()
            flash(f"PayPal error: {e}", "danger")

    custom_plans = CustomPlan.query.all()
    return render_template('admin_panel.html', custom_plans=custom_plans)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = Admin.query.filter_by(username=username).first()
        if admin and bcrypt.check_password_hash(admin.password, password):
            session['admin_logged_in'] = True
            flash("Admin login successful!", "success")
            return redirect(url_for('admin_panel'))
        else:
            flash("Invalid credentials!", "danger")

    return render_template('admin_login.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash("Logged out successfully!", "success")
    return redirect(url_for('admin_login'))

@app.route('/payment_success_admin/<email>')
def payment_success_admin(email):
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')

    payment = paypalrestsdk.Payment.find(payment_id)

    if payment.execute({"payer_id": payer_id}):
        custom_plan = CustomPlan.query.filter_by(email=email).first()
        if custom_plan:
            custom_plan.status = "Paid"
            db.session.commit()

            user = User.query.filter_by(email=email).first()
            if user:
                custom_plan_plan = Plan.query.filter_by(name="Custom").first()
                if custom_plan_plan:
                    user_plan = UserPlan.query.filter_by(user_id=user.id).first()
                    if user_plan:
                        user_plan.plan_id = custom_plan_plan.id
                    else:
                        user_plan = UserPlan(user_id=user.id, plan_id=custom_plan_plan.id)
                        db.session.add(user_plan)

                    db.session.commit()
                    flash(f"Payment received for {email}! Plan upgraded to Custom.", "success")
                    return redirect(url_for('login'))

    flash("Payment verification failed. Please contact support.", "danger")
    return redirect(url_for('admin_panel'))

from datetime import datetime, timedelta

@app.route('/<username>/dashboard', methods=["GET", "POST"])
@login_required
def dashboard(username):
    # Check if the username in URL matches the logged-in user's email
    if username != current_user.email:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('dashboard', username=current_user.email))
    form = AnalysisForm()
    
    if 'user' in session and session['user'] == current_user.email:
        analyzed_sites = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).all()
        
        # Get the latest analysis for the metrics display
        latest_analysis = analyzed_sites[0] if analyzed_sites else None
        latest_update = fetch_latest_google_update()

        # Fetch the user's most recent plan
        user_plan = UserPlan.query.filter_by(user_id=current_user.id).order_by(UserPlan.start_date.desc()).first()
        
        # If user has no plan, assign them the Free plan
        if not user_plan:
            free_plan = Plan.query.filter_by(name="Free").first()
            if free_plan:
                user_plan = UserPlan(
                    user_id=current_user.id,
                    plan_id=free_plan.id,
                    start_date=datetime.utcnow()
                )
                db.session.add(user_plan)
                db.session.commit()
                print(f"Assigned Free plan to user {current_user.id}")
            else:
                flash("Error: Could not assign Free plan. Please contact support.", "danger")
        
        plan_expired = False
        free_trial_over = False
        remaining_days = 0
        urls_remaining = 0
        analyzed_urls_count = 0

        if user_plan:
            plan = user_plan.plan

            # Get URL usage
            url_usage = UserUrlUsage.query.filter_by(user_id=current_user.id).first()
            analyzed_urls_count = url_usage.urls_used if url_usage else 0
            urls_remaining = max(0, plan.max_urls - analyzed_urls_count)

            # Check if the user has exceeded their URL limit
            if analyzed_urls_count >= plan.max_urls:
                if plan.name == "Free":
                    free_trial_over = True
                else:
                    plan_expired = True

            # Duration check - only if the plan has a duration
            if plan.duration:
                start_date = user_plan.start_date
                end_date = start_date + timedelta(days=plan.duration * 30)
                remaining_days = (end_date - datetime.utcnow()).days
                
                # Mark plan as expired if remaining days <= 0
                if remaining_days <= 0:
                    plan_expired = True
                    remaining_days = 0  # Don't show negative days
        
        # Always show plan information
        plan_info = user_plan.plan if user_plan else Plan.query.filter_by(name="Free").first()

        return render_template(
            'dashboard.html',
            form=form,
            plan=plan_info,  # Use plan_info instead of user_plan.plan
            analyzed_sites=analyzed_sites,
            latest_analysis=latest_analysis,
            analyzed_urls_count=analyzed_urls_count,
            urls_remaining=urls_remaining,
            remaining_days=remaining_days,
            plan_expired=plan_expired,
            free_trial_over=free_trial_over,
            latest_update = fetch_latest_google_update(),
            username=username,
            country=current_user.country.lower(),
            show_url_selection=True
        )
    
    # Redirect to login if user is not authenticated
    flash("Unauthorized access!", "danger")
    return redirect(url_for("login"))


# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Download route
@app.route('/download/<int:analysis_id>')
def download(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    if analysis.user_id != current_user.id:
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('dashboard', username=current_user.email))

    # Verify the file exists
    if not os.path.exists(analysis.excel_file):
        flash('The file no longer exists.', 'danger')
        return redirect(url_for('dashboard', username=current_user.email))

    return send_file(analysis.excel_file, as_attachment=True)

# Global variable to track analysis progress
analysis_status = {}


@app.route("/download_report")
@login_required 
def download_report():
    try:
        # Debug: Check session data
        print(f"Session keys: {list(session.keys())}")
        print(f"Has grade in session: {'grade' in session}")
        
        # Check for analysis data
        if not session.get('grade'):
            flash("No analysis data found. Please perform an analysis first.", "warning")
            return redirect(url_for("analyze_single_url"))
        
        # Get data from session - ensure all required fields exist
        data = {
            'metrics': session.get('metrics', {}),
            'grade': session.get('grade', 'N/A'),
            'weighted_score': session.get('weighted_score', 0),
            'category_grades': session.get('category_grades', {}),
            'recommendations': session.get('recommendations', []),
            'now': datetime.now()
        }
        
        # Debug: Print data structure
        print(f"Data structure:")
        for key, value in data.items():
            if key != 'metrics':
                print(f"  {key}: {value}")
        
        # Ensure metrics is a proper dictionary
        if data['metrics'] and isinstance(data['metrics'], dict):
            print(f"Metrics keys: {list(data['metrics'].keys())}")
            if 'URL' in data['metrics']:
                print(f"URL count: {len(data['metrics']['URL'])}")
        
        # Check if template exists
        template_path = os.path.join(app.template_folder, 'simple_report.html')
        if not os.path.exists(template_path):
            print(f"Template not found at: {template_path}")
            flash("Report template not found.", "danger")
            return redirect(url_for("analyze_single_url"))
        
        # Render HTML first for debugging
        html_content = render_template("simple_report.html", **data)
        
        # Save HTML for debugging
        debug_html_path = "debug_report_output.html"
        with open(debug_html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"Debug HTML saved to: {debug_html_path}")
        
        # Try to find wkhtmltopdf
        wkhtmltopdf_path = None
        possible_paths = [
            '/usr/bin/wkhtmltopdf',
            '/usr/local/bin/wkhtmltopdf',
            '/opt/homebrew/bin/wkhtmltopdf',
            'wkhtmltopdf',  # Try PATH
            'C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe',
        ]
        
        for path in possible_paths:
            try:
                # Check if file exists or is in PATH
                if os.path.exists(path) or path == 'wkhtmltopdf':
                    # Test by getting version
                    import subprocess
                    result = subprocess.run([path, '--version'], 
                                          capture_output=True, 
                                          text=True, 
                                          timeout=5)
                    if result.returncode == 0:
                        wkhtmltopdf_path = path
                        print(f"Found wkhtmltopdf at: {path}")
                        print(f"Version: {result.stdout.strip()}")
                        break
            except Exception as e:
                print(f"Failed with path {path}: {e}")
                continue
        
        if not wkhtmltopdf_path:
            flash("wkhtmltopdf is not installed. Please install it to generate PDF reports.", "danger")
            # Offer HTML download instead
            return download_as_html(data)
        
        try:
            # Generate PDF with options
            config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
            
            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None,
                'quiet': ''
            }
            
            print("Generating PDF...")
            pdf = pdfkit.from_string(html_content, False, configuration=config, options=options)
            print("PDF generated successfully")
            
            # Create filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"seo_report_{timestamp}.pdf"
            
            # Return PDF
            response = Response(
                pdf,
                mimetype='application/pdf',
                headers={
                    'Content-Disposition': f'attachment; filename={filename}',
                    'Content-Type': 'application/pdf'
                }
            )
            
            return response
            
        except Exception as pdf_error:
            print(f"PDF generation error: {str(pdf_error)}")
            import traceback
            traceback.print_exc()
            
            # Fallback to HTML
            flash(f"PDF generation failed: {str(pdf_error)}. Downloading as HTML instead.", "warning")
            return download_as_html(data)
        
    except Exception as e:
        print(f"Error in download_report: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f"Report generation failed: {str(e)}", "danger")
        return redirect(url_for("analyze_single_url"))

def download_as_html(data):
    """Fallback function to download as HTML"""
    html_content = render_template("simple_report.html", **data)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"seo_report_{timestamp}.html"
    
    return Response(
        html_content,
        mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


def extract_all_urls_from_sitemap_recursive(sitemap_url, max_urls=50000, visited=None):
    """
    Recursively extract all URLs from a sitemap or sitemap index.
    This properly handles WordPress/Yoast sitemap structures.
    """
    if visited is None:
        visited = set()
    
    if sitemap_url in visited:
        return []
    
    visited.add(sitemap_url)
    all_urls = []
    
    try:
        print(f"Extracting from: {sitemap_url}")
        response = requests.get(sitemap_url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Print first 500 chars for debugging
        content_preview = response.text[:500]
        print(f"Content preview: {content_preview}")
        
        # Try to parse as XML
        try:
            root = ET.fromstring(response.content)
            
            # Try multiple namespace strategies
            namespaces = [
                {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'},
                {'': ''},  # No namespace
                None  # No namespace dict
            ]
            
            sitemap_tags = []
            url_tags = []
            
            # Try to find sitemap tags with different namespace approaches
            for ns in namespaces:
                if ns is None:
                    # Find all elements named 'sitemap' regardless of namespace
                    sitemap_tags = root.findall('.//{*}sitemap')
                    url_tags = root.findall('.//{*}url')
                elif ns == {'': ''}:
                    sitemap_tags = root.findall('.//sitemap')
                    url_tags = root.findall('.//url')
                else:
                    sitemap_tags = root.findall('.//ns:sitemap', ns)
                    url_tags = root.findall('.//ns:url', ns)
                
                if sitemap_tags or url_tags:
                    print(f"Found tags with namespace: {ns}")
                    break
            
            # Check if this is a sitemap index (contains sitemap tags)
            if sitemap_tags:
                print(f"Found sitemap index with {len(sitemap_tags)} child sitemaps")
                for sitemap_tag in sitemap_tags:
                    # Try to find loc element with different approaches
                    loc = None
                    for ns in namespaces:
                        if ns is None:
                            loc = sitemap_tag.find('.//{*}loc')
                        elif ns == {'': ''}:
                            loc = sitemap_tag.find('.//loc')
                        else:
                            loc = sitemap_tag.find('.//ns:loc', ns)
                        if loc is not None:
                            break
                    
                    if loc is not None and loc.text:
                        child_url = loc.text.strip()
                        print(f"Found child sitemap: {child_url}")
                        if len(all_urls) < max_urls:
                            child_urls = extract_all_urls_from_sitemap_recursive(child_url, max_urls, visited)
                            all_urls.extend(child_urls)
                            print(f"  Extracted {len(child_urls)} URLs from {child_url}")
                return all_urls
            
            # Not a sitemap index - extract URLs directly
            if url_tags:
                for url_tag in url_tags:
                    # Try to find loc element
                    loc = None
                    for ns in namespaces:
                        if ns is None:
                            loc = url_tag.find('.//{*}loc')
                        elif ns == {'': ''}:
                            loc = url_tag.find('.//loc')
                        else:
                            loc = url_tag.find('.//ns:loc', ns)
                        if loc is not None:
                            break
                    
                    if loc is not None and loc.text:
                        url_text = loc.text.strip()
                        # Filter out non-page URLs
                        if not url_text.lower().endswith(('.pdf', '.xml', '.xsl', '.txt')):
                            all_urls.append(url_text)
                
                print(f"Found {len(all_urls)} URLs directly in {sitemap_url}")
                return all_urls
            
            # If we get here, no tags found - try BeautifulSoup as fallback
            print(f"No tags found with ElementTree, trying BeautifulSoup...")
            soup = BeautifulSoup(response.content, 'xml')
            
            # Check for sitemap index
            sitemap_tags = soup.find_all('sitemap')
            if sitemap_tags:
                print(f"Found sitemap index with {len(sitemap_tags)} child sitemaps (BeautifulSoup)")
                for sitemap_tag in sitemap_tags:
                    loc_tag = sitemap_tag.find('loc')
                    if loc_tag and loc_tag.text:
                        child_url = loc_tag.text.strip()
                        print(f"Found child sitemap via BeautifulSoup: {child_url}")
                        if len(all_urls) < max_urls:
                            child_urls = extract_all_urls_from_sitemap_recursive(child_url, max_urls, visited)
                            all_urls.extend(child_urls)
                return all_urls
            
            # Extract URLs directly with BeautifulSoup
            url_tags = soup.find_all('url')
            for url_tag in url_tags:
                loc_tag = url_tag.find('loc')
                if loc_tag and loc_tag.text:
                    url_text = loc_tag.text.strip()
                    if not url_text.lower().endswith(('.pdf', '.xml', '.xsl', '.txt')):
                        all_urls.append(url_text)
            
            print(f"Found {len(all_urls)} URLs via BeautifulSoup in {sitemap_url}")
            return all_urls
            
        except ET.ParseError as e:
            print(f"XML parse error: {e}")
            # Try BeautifulSoup as fallback
            soup = BeautifulSoup(response.content, 'xml')
            
            # Check for sitemap index
            sitemap_tags = soup.find_all('sitemap')
            if sitemap_tags:
                print(f"Found sitemap index with {len(sitemap_tags)} child sitemaps (BeautifulSoup fallback)")
                for sitemap_tag in sitemap_tags:
                    loc_tag = sitemap_tag.find('loc')
                    if loc_tag and loc_tag.text:
                        child_url = loc_tag.text.strip()
                        if len(all_urls) < max_urls:
                            child_urls = extract_all_urls_from_sitemap_recursive(child_url, max_urls, visited)
                            all_urls.extend(child_urls)
                return all_urls
            
            # Extract URLs directly
            url_tags = soup.find_all('url')
            for url_tag in url_tags:
                loc_tag = url_tag.find('loc')
                if loc_tag and loc_tag.text:
                    url_text = loc_tag.text.strip()
                    if not url_text.lower().endswith(('.pdf', '.xml', '.xsl', '.txt')):
                        all_urls.append(url_text)
            
            print(f"Found {len(all_urls)} URLs via BeautifulSoup in {sitemap_url}")
            return all_urls
            
    except Exception as e:
        print(f"Error extracting from {sitemap_url}: {e}")
        import traceback
        traceback.print_exc()
        return []
    
    return all_urls


def fetch_complete_sitemap_urls(base_url):
    """
    Fetch all URLs from a website's sitemap, handling both sitemap indexes and child sitemaps.
    Returns a dictionary with sitemap info and all URLs.
    """
    result = {
        'sitemap_index_url': None,
        'child_sitemaps': [],
        'all_urls': [],
        'total_urls': 0,
        'errors': []
    }
    
    try:
        # Find the sitemap
        sitemap_info = guess_sitemap_url(base_url)
        
        if isinstance(sitemap_info, dict):
            sitemap_index_url = sitemap_info.get('sitemap_url')
            result['sitemap_index_url'] = sitemap_index_url
        else:
            sitemap_index_url = sitemap_info
            result['sitemap_index_url'] = sitemap_index_url
        
        if not sitemap_index_url:
            result['errors'].append(f"No sitemap found for {base_url}")
            return result
        
        print(f"Fetching complete sitemap from: {sitemap_index_url}")
        
        # Extract all URLs recursively
        all_urls = extract_all_urls_from_sitemap_recursive(sitemap_index_url)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in all_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        result['all_urls'] = unique_urls
        result['total_urls'] = len(unique_urls)
        
        print(f"Successfully extracted {result['total_urls']} unique URLs from sitemap")
        
        # Debug: Print first 5 URLs
        if unique_urls:
            print(f"Sample URLs from sitemap:")
            for i, url in enumerate(unique_urls[:5]):
                print(f"  {i+1}. {url}")
        
        return result
        
    except Exception as e:
        result['errors'].append(str(e))
        print(f"Error in fetch_complete_sitemap_urls: {e}")
        import traceback
        traceback.print_exc()
        return result


def check_url_in_sitemap(target_url):
    """
    Check if a specific URL exists in the website's sitemap.
    Properly handles WordPress/Yoast sitemap structures.
    """
    result = {
        'found': False,
        'sitemap_index_url': None,
        'child_sitemap_url': None,
        'matched_url': None,
        'all_sitemap_urls': [],
        'total_urls': 0,
        'error': None
    }
    
    try:
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Get complete sitemap data
        sitemap_data = fetch_complete_sitemap_urls(base_url)
        
        result['sitemap_index_url'] = sitemap_data.get('sitemap_index_url')
        result['all_sitemap_urls'] = sitemap_data.get('all_urls', [])
        result['total_urls'] = sitemap_data.get('total_urls', 0)
        
        if sitemap_data.get('errors'):
            result['error'] = '; '.join(sitemap_data['errors'])
            return result
        
        # Normalize target URL for comparison
        target_normalized = target_url.rstrip('/').lower()
        target_without_www = target_normalized.replace('://www.', '://')
        target_with_www = target_normalized.replace('://', '://www.')
        
        target_variations = {
            target_normalized,
            target_without_www,
            target_with_www,
            target_normalized + '/',
            target_without_www + '/',
            target_with_www + '/',
        }
        
        # Check if URL exists in sitemap URLs
        for sitemap_url in result['all_sitemap_urls']:
            sitemap_normalized = sitemap_url.rstrip('/').lower()
            
            if sitemap_normalized in target_variations or target_normalized in [sitemap_normalized, sitemap_normalized + '/']:
                result['found'] = True
                result['matched_url'] = sitemap_url
                print(f"✓ URL found in sitemap: {sitemap_url}")
                break
        
        if not result['found']:
            print(f"✗ URL not found in sitemap (checked {result['total_urls']} URLs)")
            
    except Exception as e:
        result['error'] = str(e)
        print(f"Error in check_url_in_sitemap: {e}")
    
    return result


@app.route("/single-url", methods=["GET", "POST"])
def analyze_single_url():
    """Single URL analysis - requires login"""
    # Check if user is logged in
    if not current_user.is_authenticated:
        flash("Please login to analyze a URL.", "info")
        return redirect(url_for("login", next=request.url))
    
    from tasks import analyze_single_url_task
    form = AnalysisForm()
    latest_update = fetch_latest_google_update()
    
    if form.validate_on_submit():
        try:
            url = form.url.data.strip()
            
            if not url:
                flash("Please provide a valid URL.", "danger")
                return redirect(url_for("analyze_single_url"))
            
            # Check if it's a valid URL
            if not is_valid_url(url):
                flash("Invalid URL format. Please include http:// or https://", "danger")
                return redirect(url_for("analyze_single_url"))

            # Use the new function
            sitemap_check = check_url_in_sitemap(url)
            
            sitemap_status = "not_checked"
            sitemap_warning = None
            sitemap_url = sitemap_check.get('sitemap_index_url')

            if sitemap_check.get('error'):
                sitemap_status = "sitemap_error"
                sitemap_warning = sitemap_check['error']
                print(f"[single-url] Sitemap error: {sitemap_warning}")
            elif sitemap_check.get('found'):
                sitemap_status = "found_in_sitemap"
                print(f"[single-url] ✓ URL found in sitemap: {url}")
                print(f"[single-url] Total URLs in sitemap: {sitemap_check['total_urls']}")
            else:
                sitemap_status = "not_in_sitemap"
                sitemap_warning = (
                    f"This URL was not found in the sitemap. "
                    f"The sitemap contains {sitemap_check['total_urls']} URLs, "
                    f"but this specific URL is not listed."
                )
                print(f"[single-url] URL not found in sitemap (checked {sitemap_check['total_urls']} URLs)")
            # ─────────────────────────────────────────────────────────────────
            
            # Create a unique job ID
            job_id = str(uuid.uuid4())
            
            # Create job record in database
            single_job = SingleUrlJob(
                id=job_id,
                user_id=current_user.id,
                url=url,
                status="queued",
                progress=0,
                message="Starting analysis...",
                created_at=datetime.utcnow()
            )
            db.session.add(single_job)
            db.session.commit()
            
            # Store initial job data in Redis (temporary storage for frontend)
            redis_conn.setex(f"single_url_job:{job_id}", 3600, json.dumps({
                "url": url,
                "status": "queued",
                "progress": 0,
                "message": "Starting analysis...",
                "created_at": datetime.utcnow().isoformat(),
                "user_id": current_user.id,
                # Sitemap metadata passed along for display in results
                "sitemap_url":    sitemap_url,
                "sitemap_status": sitemap_status,
                "sitemap_warning": sitemap_warning,
            }))
            
            # Start the background task
            task = analyze_single_url_task.send(url, job_id, current_user.id)
            
            # Build response – include sitemap info so the frontend can show it
            response_payload = {
                "success": True,
                "message": "Analysis started in background",
                "job_id": job_id,
                "redirect": url_for("single_url_results", job_id=job_id),
                "sitemap_status":  sitemap_status,
                "sitemap_url":     sitemap_url,
                "sitemap_warning": sitemap_warning,
            }

            return jsonify(response_payload)
            
        except Exception as e:
            print(f"Error in analyze_single_url: {str(e)}")
            import traceback
            traceback.print_exc()
            flash(f"An error occurred: {str(e)}", "danger")
            return redirect(url_for("analyze_single_url"))
    
    # Handle GET requests
    return render_template("index.html", 
                         form=form, 
                         latest_update=latest_update,
                         metrics=None,
                         grade=None,
                         category_grades=None,
                         weighted_score=None,
                         recommendations=[],
                         from_post=False,
                         performance_metrics=None,
                         hreflang_tags=[],
                         schema_types=[],
                         ssl_info={
                             'has_ssl': False,
                             'expiry_date': 'N/A',
                             'days_remaining': 'N/A'
                         },
                         images_without_alt=0,
                         screenshots={},
                         user_logged_in=True)

@app.route("/single_url_results/<job_id>")
def single_url_results(job_id):
    """Page to display single URL analysis results - accessible without login"""
    
    # First, try to get job from database
    single_job = SingleUrlJob.query.get(job_id)
    
    if not single_job:
        # Check Redis as fallback
        job_data = redis_conn.get(f"single_url_job:{job_id}")
        if not job_data:
            flash("Analysis job not found or expired.", "danger")
            return redirect(url_for("analyze_single_url"))
        job_data = json.loads(job_data)
    else:
        # Convert database job to dict format
        job_data = {
            "url": single_job.url,
            "status": single_job.status,
            "progress": single_job.progress,
            "message": single_job.message,
            "created_at": single_job.created_at.isoformat() if single_job.created_at else None,
            "user_id": single_job.user_id,
            "session_id": single_job.session_id
        }
    
    # Check authorization
    if current_user.is_authenticated:
        # For logged-in users: check if they own this job OR it's an anonymous job
        if single_job and single_job.user_id and single_job.user_id != current_user.id:
            flash("You don't have permission to view this analysis.", "danger")
            return redirect(url_for("analyze_single_url"))
    else:
        # For anonymous users: check session ID
        if single_job and single_job.session_id and single_job.session_id != session.sid:
            flash("This analysis belongs to a different session.", "info")
            return redirect(url_for("analyze_single_url"))
    
    # If job is completed, fetch results from Redis
    if job_data.get("status") == "completed" or (single_job and single_job.status == "completed"):
        # Get results from Redis
        result_data = redis_conn.get(f"single_url_job:{job_id}")
        if result_data:
            result = json.loads(result_data).get("result", {})
        else:
            # Try to get from database job
            if single_job and single_job.results_data:
                result = single_job.results_data
            else:
                flash("Analysis results not found.", "danger")
                return redirect(url_for("analyze_single_url"))

        if result.get("success"):
            # DEBUG: Print available keys
            print(f"DEBUG: Result keys: {list(result.keys())}")
            
            # Get keyword analysis from result - IMPORTANT: Ensure it exists
            keyword_analysis = result.get("keyword_analysis", {})
            print(f"DEBUG: Keyword analysis type: {type(keyword_analysis)}")
            print(f"DEBUG: Keyword analysis keys: {keyword_analysis.keys() if isinstance(keyword_analysis, dict) else 'Not a dict'}")
            print(f"DEBUG: Keyword analysis has 'extracted_keywords': {'extracted_keywords' in keyword_analysis}")
            
            # Check if keyword analysis was actually performed
            if keyword_analysis and isinstance(keyword_analysis, dict):
                if 'extracted_keywords' not in keyword_analysis:
                    print("DEBUG: No extracted_keywords in keyword_analysis, creating fallback")
                    keyword_analysis = {
                        "error": "Keyword analysis was not performed on this URL.",
                        "url": result.get("url", "Unknown"),
                        "extracted_keywords": [],
                        "keyword_suggestions": [],
                        "summary": {
                            'total_keywords': 0,
                            'long_tail_keywords': 0,
                            'avg_search_volume': 0,
                            'avg_cpc': 0
                        }
                    }
            
            # Store ALL data in session for download_report access
            session.update({
                'metrics': result.get("metrics"),
                'grade': result.get("grade"),
                'weighted_score': result.get("weighted_score"),
                'category_grades': result.get("category_grades"),
                'recommendations': result.get("recommendations", []),
                'recent_job_id': job_id,
                'analysis_data': result,
                'job_owner_user_id': current_user.id if current_user.is_authenticated else None,
                'job_owner_session_id': session.sid if not current_user.is_authenticated else None,
                'keyword_analysis': keyword_analysis  # Store in session too
            })
            session.modified = True
            
            # Get other data
            responsive_image_issues_details = result.get("responsive_image_issues_details", [])
            
            return render_template("index.html",
                form=AnalysisForm(),
                metrics=result.get("metrics"),
                grade=result.get("grade"),
                weighted_score=result.get("weighted_score"),
                category_grades=result.get("category_grades"),
                recommendations=result.get("recommendations", []),
                from_post=True,
                performance_metrics=result.get("performance_metrics"),
                hreflang_tags=result.get("hreflang_tags", []),
                schema_types=result.get("schema_types", []),
                ssl_info=result.get("ssl_info", {
                    'has_ssl': False,
                    'expiry_date': 'N/A',
                    'days_remaining': 'N/A'
                }),
                images_without_alt=result.get("images_without_alt", 0),
                screenshots=result.get("screenshots", {}),
                latest_update=fetch_latest_google_update(),
                responsive_image_issues_details=responsive_image_issues_details,
                # Ensure keyword_analysis is always passed, even if empty
                keyword_analysis=keyword_analysis,
                user_logged_in=current_user.is_authenticated,
                current_job_id=job_id
            )
        else:
            flash(f"Analysis failed: {result.get('error', 'Unknown error')}", "danger")
            return redirect(url_for("analyze_single_url"))
    
    # If job is still processing, show loading page
    return render_template("single_url_loading.html", 
                         job_id=job_id,
                         url=job_data.get("url"),
                         progress=job_data.get("progress", 0),
                         message=job_data.get("message", "Processing..."),
                         user_logged_in=current_user.is_authenticated)

# Update the single_url_progress route to allow access without login:
@app.route("/single_url_progress/<job_id>")
def single_url_progress(job_id):
    """SSE endpoint for single URL analysis progress - accessible without login"""
    
    def generate():
        last_progress = 0
        with app.app_context():
            while True:
                # Get job data from Redis
                job_data = redis_conn.get(f"single_url_job:{job_id}")
                
                if not job_data:
                    yield f"data: {json.dumps({'error': 'Job not found', 'status': 'failed'})}\n\n"
                    break
                
                job_data = json.loads(job_data)
                
                # Only send update if progress changed
                if job_data.get("progress", 0) != last_progress:
                    data = {
                        "status": job_data.get("status", "processing"),
                        "progress": job_data.get("progress", 0),
                        "message": job_data.get("message", "Processing..."),
                        "url": job_data.get("url", "")
                    }
                    
                    if job_data.get("status") == "completed":
                        data["result_ready"] = True
                        data["redirect"] = url_for("single_url_results", job_id=job_id)
                    
                    yield f"data: {json.dumps(data)}\n\n"
                    last_progress = job_data.get("progress", 0)
                
                # Check if job is finished
                if job_data.get("status") in ["completed", "failed"]:
                    break
                
                time.sleep(1)
    
    return Response(generate(), mimetype="text/event-stream",
                   headers={
                       'Cache-Control': 'no-cache',
                       'Connection': 'keep-alive',
                       'X-Accel-Buffering': 'no'
                   })

# Update the check_single_url_job route:
@app.route("/check_single_url_job/<job_id>")
def check_single_url_job(job_id):
    """Check single URL job status - accessible without login"""
    job_data = redis_conn.get(f"single_url_job:{job_id}")
    
    if not job_data:
        return jsonify({"error": "Job not found"}), 404
    
    job_data = json.loads(job_data)
    return jsonify(job_data)

"""@app.route("/", methods=["GET", "POST"])
def analyze_single_url():
    form = AnalysisForm()
    
    if form.validate_on_submit():
        try:
            url = form.url.data.strip()
            
            if not url:
                flash("Please provide a valid URL.", "danger")
                return redirect(url_for("analyze_single_url"))

            # Analyze the single URL
            seo_metrics = analyze_page(url)
            if not seo_metrics:
                flash("Failed to analyze the URL.", "danger")
                return redirect(url_for("analyze_single_url"))

            api_key = app.config["GOOGLE_API_KEY"]
            desktop_metrics = fetch_pagespeed_metrics(url, "desktop", api_key)
            mobile_metrics = fetch_pagespeed_metrics(url, "mobile", api_key)
            
            moz_access_id = app.config.get("MOZ_ACCESS_ID")
            moz_secret_key = app.config.get("MOZ_SECRET_KEY")

            # Always fetch MOZ metrics (no login required now)
            moz_metrics = fetch_moz_metrics(url, moz_access_id, moz_secret_key)
            recommendations = generate_recommendations(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics)
            grade_results = singlepage_grade(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics)
            latest_update = fetch_latest_google_update()

            
            # Prepare the metrics dictionary for the single URL
            metrics = {
                "URL": [url],
                "Last Modified": ["N/A"],
                "Meta Title": [seo_metrics.get("Meta Title", "N/A")],
                "Meta Title Character Count": [seo_metrics.get("Meta Title Character Count", "N/A")],
                "Meta Description": [seo_metrics.get("Meta Description", "N/A")],
                "Meta Description Character Count": [seo_metrics.get("Meta Description Character Count", "N/A")],
                "Word Count": [seo_metrics.get("Word Count", "N/A")],
                "H1 Tags": [seo_metrics.get("H1 Tags", "N/A")],
                "H2 Tags": [seo_metrics.get("H2 Tags", "N/A")],
                "Canonical Tag": [seo_metrics.get("Canonical Tag", "N/A")],
                "Largest Image Name": [seo_metrics.get("Largest Image Name", "N/A")],
                "Largest Image Size (KB)": [seo_metrics.get("Largest Image Size (KB)", "N/A")],
                "Structured Data": [seo_metrics.get("Structured Data", "N/A")],
                "Internal Links": [seo_metrics.get("Internal Links", "N/A")],
                "External Links": [seo_metrics.get("External Links", "N/A")],
                "Performance Score (Desktop)": [desktop_metrics.get('Performance Score', 'N/A')],
                "First Contentful Paint (Desktop)": [desktop_metrics.get('First Contentful Paint', 'N/A')],
                "Speed Index (Desktop)": [desktop_metrics.get('Speed Index', 'N/A')],
                "Time to Interactive (Desktop)": [desktop_metrics.get('Time to Interactive', 'N/A')],
                "First Meaningful Paint (Desktop)": [desktop_metrics.get('First Meaningful Paint', 'N/A')],
                "CLS Lighthouse (Desktop)": [desktop_metrics.get('CLS Lighthouse', 'N/A')],
                "LCP Lighthouse (Desktop)": [desktop_metrics.get('LCP Lighthouse', 'N/A')],
                "Performance Score (Mobile)": [mobile_metrics.get('Performance Score', 'N/A')],
                "First Contentful Paint (Mobile)": [mobile_metrics.get('First Contentful Paint', 'N/A')],
                "Speed Index (Mobile)": [mobile_metrics.get('Speed Index', 'N/A')],
                "Time to Interactive (Mobile)": [mobile_metrics.get('Time to Interactive', 'N/A')],
                "First Meaningful Paint (Mobile)": [mobile_metrics.get('First Meaningful Paint', 'N/A')],
                "CLS Lighthouse (Mobile)": [mobile_metrics.get('CLS Lighthouse', 'N/A')],
                "LCP Lighthouse (Mobile)": [mobile_metrics.get('LCP Lighthouse', 'N/A')],
                "Broken Links": [seo_metrics.get("Broken Links", "N/A")],
                "Image Details": [seo_metrics.get("Image Details", [])],
                "Indexability": [seo_metrics.get("Indexability", "N/A")],
                "Response Code": [seo_metrics.get("Response Code", "N/A")],

                # Add Moz metrics to the output
                "Domain Authority": [moz_metrics.get("Domain Authority", "N/A")],
                "Page Authority": [moz_metrics.get("Page Authority", "N/A")],
                "Spam Score": [moz_metrics.get("Spam Score", "N/A")],
                "Link Propensity": [moz_metrics.get("Link Propensity", "N/A")],
                "Total Backlinks": [moz_metrics.get("Total Backlinks", "N/A")],
                "Backlink Domain": [moz_metrics.get("Backlink Domain", "N/A")]
            }

            # Store metrics in session if needed for redirects
            session['metrics'] = metrics
            session['grade'] = grade_results['overall']
            session['weighted_score'] = grade_results['weighted_score']
            session['category_grades'] = grade_results['categories']
            session['recommendations'] = recommendations
            session.modified = True
            
            # Render the template with both form and metrics
            return render_template("index.html", form=form, latest_update=latest_update, metrics=metrics, grade=grade_results['overall'], category_grades=grade_results['categories'], weighted_score=grade_results['weighted_score'], recommendations=recommendations, from_post=True)

        except Exception as e:
            flash(f"An error occurred during analysis: {str(e)}", "danger")
            return redirect(url_for("analyze_single_url"))
    
    # Handle GET requests or when form validation fails
    metrics = session.pop('metrics', None)
    recommendations = []
    return render_template("index.html", form=form, metrics=metrics, grade=None, category_grades=None, weighted_score=None, recommendations=recommendations, from_post=False)"""




"""@app.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    from tasks import analyze_sitemap_task
    form = AnalysisForm()
    
    if form.validate_on_submit():
        try:
            if "user" not in session or session["user"] != current_user.email:
                return jsonify({"success": False, "message": "Unauthorized"}), 401

            user_plan = UserPlan.query.filter_by(user_id=current_user.id)\
                                    .order_by(UserPlan.start_date.desc())\
                                    .first()
            if not user_plan:
                return jsonify({"success": False, "message": "Plan required"}), 402

            url_usage = UserUrlUsage.query.filter_by(user_id=current_user.id).first()
            analyzed_urls_count = url_usage.urls_used if url_usage else 0
            
            if analyzed_urls_count >= user_plan.plan.max_urls:
                return jsonify({
                    "success": False,
                    "message": f"URL limit reached ({user_plan.plan.max_urls})"
                }), 403

            url = form.url.data.strip()
            if not is_valid_url(url):
                return jsonify({"success": False, "message": "Invalid URL"}), 400

            # Create analysis job record
            job = AnalysisJob(
                id=str(uuid.uuid4()),
                user_id=current_user.id,
                website_url=url,
                status="queued",
                progress=0
            )
            db.session.add(job)
            db.session.commit()

            # Start task with job ID
            task = analyze_sitemap_task.send(
                current_user.id,
                url,
                user_plan.plan.max_urls,
                analyzed_urls_count,
                job.id
            )
            
            # Update job with task_id
            job.task_id = task.message_id
            db.session.commit()
            
            return jsonify({
                "success": True,
                "message": "Analysis started",
                "task_id": task.message_id,
                "job_id": job.id
            })
            
        except Exception as e:
            app.logger.error(f"Analysis error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "Internal error"
            }), 500

    return render_template("dashboard.html", form=form, username=current_user.username)"""

"""@app.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    from tasks import analyze_sitemap_task
    form = AnalysisForm()
    
    if form.validate_on_submit():
        try:
            if "user" not in session or session["user"] != current_user.email:
                return jsonify({"success": False, "message": "Unauthorized"}), 401

            user_plan = UserPlan.query.filter_by(user_id=current_user.id)\
                                    .order_by(UserPlan.start_date.desc())\
                                    .first()
            if not user_plan:
                return jsonify({"success": False, "message": "Plan required"}), 402

            # Check if plan has expired (remaining days <= 0)
            if user_plan.plan.duration:
                end_date = user_plan.start_date + timedelta(days=user_plan.plan.duration * 30)
                if datetime.utcnow() > end_date:
                    return jsonify({
                        "success": False,
                        "message": "Your plan has expired. Please upgrade to continue using the service.",
                        "redirect": url_for("select_plan")
                    }), 403

            url_usage = UserUrlUsage.query.filter_by(user_id=current_user.id).first()
            analyzed_urls_count = url_usage.urls_used if url_usage else 0
            
            if analyzed_urls_count >= user_plan.plan.max_urls:
                return jsonify({
                    "success": False,
                    "message": f"URL limit reached ({user_plan.plan.max_urls})"
                }), 403

            url = form.url.data.strip()
            if not is_valid_url(url):
                return jsonify({"success": False, "message": "Invalid URL"}), 400

            # Create analysis job record
            job = AnalysisJob(
                id=str(uuid.uuid4()),
                user_id=current_user.id,
                website_url=url,
                status="queued",
                progress=0
            )
            db.session.add(job)
            db.session.commit()

            # Start task with job ID
            task = analyze_sitemap_task.send(
                current_user.id,
                url,
                user_plan.plan.max_urls,
                analyzed_urls_count,
                job.id
            )
            
            # Update job with task_id
            job.task_id = task.message_id
            db.session.commit()
            
            return jsonify({
                "success": True,
                "message": "Analysis started",
                "task_id": task.message_id,
                "job_id": job.id
            })
            
        except Exception as e:
            app.logger.error(f"Analysis error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "Internal error"
            }), 500

    return render_template("dashboard.html", form=form, username=current_user.username)"""

@app.route("/analyze_with_selection", methods=["GET", "POST"])
@login_required
def analyze_with_selection():
    """Route to display URLs from sitemap for user selection"""
    form = AnalysisForm()
    url_selection_form = URLSelectionForm()
    
    if request.method == "POST":
        if form.validate_on_submit():
            try:
                url = form.url.data.strip()
                
                if not is_valid_url(url):
                    flash("Invalid URL format.", "danger")
                    return redirect(url_for("analyze_with_selection"))
                
                # Handle both direct sitemap URLs and website URLs
                parsed_url = urlparse(url)
                
                if url.endswith(".xml"):
                    # User provided a sitemap URL directly
                    sitemap_url = url
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                else:
                    # User provided a website URL, need to find sitemap
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                    
                    # IMPORTANT: Use the SAME logic as in /analyze route
                    # Try to find sitemap with comprehensive checking
                    try:
                        sitemap_result = guess_sitemap_url(base_url)
                        
                        if isinstance(sitemap_result, dict):
                            sitemap_url = sitemap_result.get('sitemap_url')
                            sitemap_exists = sitemap_result.get('exists', False)
                        else:
                            sitemap_url = sitemap_result
                            sitemap_exists = bool(sitemap_url)
                        
                        # If not found, try the robust extract_all_urls_from_sitemap on default location
                        if not sitemap_url or not sitemap_exists:
                            # Try default sitemap.xml
                            default_sitemap = urljoin(base_url, "/sitemap.xml")
                            try:
                                # Test if it exists
                                response = requests.head(default_sitemap, headers=headers, timeout=10)
                                if response.status_code == 200:
                                    sitemap_url = default_sitemap
                                    sitemap_exists = True
                                else:
                                    # Try sitemap_index.xml (common for WordPress)
                                    alt_sitemap = urljoin(base_url, "/sitemap_index.xml")
                                    response = requests.head(alt_sitemap, headers=headers, timeout=10)
                                    if response.status_code == 200:
                                        sitemap_url = alt_sitemap
                                        sitemap_exists = True
                            except:
                                # If HEAD fails, still try to extract URLs
                                sitemap_url = default_sitemap
                                sitemap_exists = False  # We'll try anyway
                        
                        # ALWAYS try to extract URLs even if guess_sitemap_url failed
                        # This is the key fix - don't rely solely on guess_sitemap_url
                        if not sitemap_exists:
                            print(f"Warning: Sitemap not confirmed to exist, but trying to extract URLs from: {sitemap_url}")
                            
                    except Exception as e:
                        print(f"Warning: Failed to guess sitemap: {str(e)}")
                        # Fallback to default sitemap location
                        sitemap_url = urljoin(base_url, "/sitemap.xml")
                
                print(f"Using sitemap URL: {sitemap_url}")
                
                # IMPORTANT: Use the SAME robust extraction as in /analyze route
                # This function handles WordPress sitemap_index.xml, regular sitemaps, and sitemap indexes
                all_urls = extract_all_urls_from_sitemap(sitemap_url)
                
                # If no URLs found, try alternative approaches (same as /analyze)
                if not all_urls:
                    print("Primary extraction failed, trying alternative methods...")
                    
                    # Try fetch_and_parse_sitemap (alternative parser)
                    all_urls = fetch_and_parse_sitemap(sitemap_url)
                    
                    if not all_urls:
                        # Try fetch_sitemap_urls (for sitemap indexes)
                        sitemap_entries = fetch_sitemap_urls(sitemap_url)
                        if sitemap_entries:
                            for sitemap_entry, _ in sitemap_entries:
                                child_urls = fetch_urls_from_sitemap(sitemap_entry)
                                if child_urls:
                                    all_urls.extend(child_urls)
                    
                    # If still no URLs, try fetch_sitemap_data (combined approach)
                    if not all_urls:
                        all_urls = fetch_sitemap_data(sitemap_url)
                
                if not all_urls:
                    # Last resort: try to crawl homepage for links
                    try:
                        print("Attempting to extract links from homepage...")
                        response = requests.get(base_url, headers=headers, timeout=10)
                        soup = BeautifulSoup(response.content, 'html.parser')
                        links = soup.find_all('a', href=True)
                        for link in links[:50]:  # Limit to first 50
                            href = link['href']
                            if href.startswith('http'):
                                all_urls.append(href)
                            elif href.startswith('/'):
                                all_urls.append(urljoin(base_url, href))
                        print(f"Found {len(all_urls)} links from homepage")
                    except Exception as e:
                        print(f"Failed to crawl homepage: {e}")
                
                if not all_urls:
                    flash("No URLs found in the sitemap or website. Please check if the sitemap exists.", "danger")
                    return redirect(url_for("analyze_with_selection"))
                
                # Remove duplicates
                all_urls = list(dict.fromkeys(all_urls))
                print(f"Total unique URLs found: {len(all_urls)}")
                
                # Generate a unique session key for this analysis
                session_key = f"url_selection_{current_user.id}_{datetime.now().timestamp()}"
                
                # Store URLs in Redis instead of session cookie
                redis_conn.setex(
                    f"sitemap_urls:{session_key}", 
                    3600,  # Expire in 1 hour
                    json.dumps({
                        'urls': all_urls,
                        'sitemap_url': sitemap_url,
                        'original_url': url,
                        'total_count': len(all_urls)
                    })
                )
                
                # Store only the key in session (small size)
                session['url_selection_key'] = session_key
                session['display_count'] = min(100, len(all_urls))
                session['total_url_count'] = len(all_urls)
                
                # For UI, show only first 100 URLs for selection
                display_urls = all_urls[:100]
                
                flash(f"Found {len(all_urls)} URLs. You can select up to 100 for analysis.", "info")
                
                return render_template("url_selection.html",
                                     form=form,
                                     selection_form=url_selection_form,
                                     url_count=len(display_urls),
                                     total_url_count=len(all_urls),
                                     urls=display_urls)
            
            except Exception as e:
                flash(f"Error: {str(e)}", "danger")
                return redirect(url_for("analyze_with_selection"))
        else:
            flash("Please enter a valid URL.", "danger")
    
    # Clear session data on GET request
    if request.method == "GET":
        session.pop('url_selection_key', None)
        session.pop('display_count', None)
        session.pop('total_url_count', None)
    
    return render_template("url_selection.html",
                         form=form,
                         selection_form=url_selection_form,
                         url_count=0,
                         total_url_count=0,
                         urls=[])

# Add this route to main.py
@app.route('/api/get_sitemap_urls', methods=['POST'])
@login_required
def get_sitemap_urls():
    """API endpoint to fetch sitemap URLs"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({"success": False, "message": "URL is required"}), 400
        
        if not is_valid_url(url):
            return jsonify({"success": False, "message": "Invalid URL"}), 400
        
        # Handle both direct sitemap URLs and website URLs
        parsed_url = urlparse(url)
        
        if url.endswith(".xml"):
            sitemap_url = url
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        else:
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
            
            # Try to find sitemap
            sitemap_result = guess_sitemap_url(base_url)
            if isinstance(sitemap_result, dict):
                sitemap_url = sitemap_result.get('sitemap_url', urljoin(base_url, "/sitemap.xml"))
            else:
                sitemap_url = sitemap_result
        
        # Extract URLs from sitemap
        all_urls = extract_all_urls_from_sitemap(sitemap_url)
        
        if not all_urls:
            return jsonify({"success": False, "message": "No URLs found in sitemap"}), 404
        
        # Limit to 500 URLs for performance
        if len(all_urls) > 500:
            all_urls = all_urls[:500]
        
        return jsonify({
            "success": True,
            "urls": all_urls,
            "sitemap_url": sitemap_url,
            "total": len(all_urls)
        })
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/analyze_with_selection_large", methods=["GET", "POST"])
@login_required
def analyze_with_selection_large():
    """Special route for sites with massive sitemaps"""
    form = AnalysisForm()
    
    if form.validate_on_submit():
        try:
            url = form.url.data.strip()
            
            if not is_valid_url(url):
                flash("Invalid URL format.", "danger")
                return redirect(url_for("analyze_with_selection_large"))
            
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
            
            # Check if it's a direct sitemap URL
            if url.endswith(".xml"):
                sitemap_url = url
            else:
                sitemap_url = urljoin(base_url, "/sitemap.xml")
            
            # Just get the sitemap URL count without extracting all URLs
            # Use a HEAD request to check if it exists
            try:
                response = requests.head(sitemap_url, headers=headers, timeout=10)
                if response.status_code != 200:
                    flash(f"Sitemap not found at {sitemap_url}", "warning")
                    return redirect(url_for("analyze_with_selection_large"))
            except:
                flash(f"Cannot access sitemap at {sitemap_url}", "warning")
                return redirect(url_for("analyze_with_selection_large"))
            
            # For large sites, offer sampling instead of full extraction
            session['large_site_sitemap'] = sitemap_url
            session['large_site_original'] = url
            
            return render_template("large_site_options.html", 
                                 sitemap_url=sitemap_url,
                                 original_url=url)
            
        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
            return redirect(url_for("analyze_with_selection_large"))
    
    return render_template("large_site_analyze.html", form=form)

"""@app.route("/analyze_with_selection", methods=["GET", "POST"])
@login_required
def analyze_with_selection():
    ""Route to display URLs from sitemap for user selection""
    form = AnalysisForm()
    url_selection_form = URLSelectionForm()
    
    if request.method == "POST":
        if form.validate_on_submit():
            try:
                url = form.url.data.strip()
                
                if not is_valid_url(url):
                    flash("Invalid URL format.", "danger")
                    return redirect(url_for("analyze_with_selection"))
                
                # Handle both direct sitemap URLs and website URLs
                parsed_url = urlparse(url)
                
                if url.endswith(".xml"):
                    # User provided a sitemap URL directly
                    sitemap_url = url
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                else:
                    # User provided a website URL, need to find sitemap
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                    
                    # Try to find sitemap, but don't fail if check fails
                    try:
                        sitemap_result = guess_sitemap_url(base_url)
                        
                        if isinstance(sitemap_result, dict):
                            sitemap_url = sitemap_result.get('sitemap_url')
                            sitemap_exists = sitemap_result.get('exists', False)
                        else:
                            sitemap_url = sitemap_result
                            sitemap_exists = bool(sitemap_url)
                        
                        # Even if guess_sitemap_url fails, try the default sitemap.xml
                        if not sitemap_url or not sitemap_exists:
                            sitemap_url = urljoin(base_url, "/sitemap.xml")
                            
                    except Exception as e:
                        print(f"Warning: Failed to guess sitemap: {str(e)}")
                        # Fallback to default sitemap location
                        sitemap_url = urljoin(base_url, "/sitemap.xml")
                
                print(f"Using sitemap URL: {sitemap_url}")
                
                # Extract URLs from sitemap WITH SMART LIMITING
                print("Extracting URLs from sitemap...")
                
                # For very large sites, we need a different approach
                # First, try to get a sample to see the size
                MAX_URLS_TO_EXTRACT = 50000  # Maximum URLs to extract
                MAX_URLS_TO_STORE = 20000    # Maximum URLs to store in Redis
                MAX_URLS_TO_DISPLAY = 100    # Maximum URLs to display in UI
                
                # Use extract_all_urls_from_sitemap but with early termination
                try:
                    all_urls = []
                    print("Starting URL extraction (this may take a while for large sites)...")
                    
                    # We'll use a modified approach for large sites
                    # First, check if it's a sitemap index
                    try:
                        response = requests.get(sitemap_url, headers=headers, timeout=30)
                        root = ET.fromstring(response.content)
                        namespace = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                        
                        # Check for sitemap index
                        sitemap_tags = root.findall('.//ns:sitemap', namespace)
                        if sitemap_tags:
                            print(f"Found sitemap index with {len(sitemap_tags)} child sitemaps")
                            # For large sites with many sitemaps, sample from first few
                            if len(sitemap_tags) > 5:
                                print("Large sitemap index detected - sampling from first 5 sitemaps")
                                sitemap_tags = sitemap_tags[:5]
                            
                            # Extract URLs from child sitemaps with limits
                            urls_extracted = 0
                            for sitemap_tag in sitemap_tags:
                                loc = sitemap_tag.find('ns:loc', namespace)
                                if loc is not None and loc.text:
                                    child_url = loc.text.strip()
                                    print(f"Extracting from child sitemap: {child_url}")
                                    
                                    # Extract from child sitemap with limit
                                    child_urls = extract_all_urls_from_sitemap(child_url)
                                    all_urls.extend(child_urls)
                                    urls_extracted += len(child_urls)
                                    
                                    if urls_extracted >= MAX_URLS_TO_EXTRACT:
                                        print(f"Reached extraction limit of {MAX_URLS_TO_EXTRACT} URLs")
                                        break
                        
                        # If not a sitemap index or no child sitemaps found
                        if not all_urls:
                            all_urls = extract_all_urls_from_sitemap(sitemap_url)
                            
                    except Exception as e:
                        print(f"Error in smart extraction: {str(e)}")
                        # Fallback to regular extraction
                        all_urls = extract_all_urls_from_sitemap(sitemap_url)
                    
                except Exception as e:
                    print(f"Error extracting URLs: {str(e)}")
                    flash(f"Error extracting URLs: {str(e)}", "danger")
                    return redirect(url_for("analyze_with_selection"))
                
                if not all_urls:
                    flash("No URLs found in the sitemap.", "danger")
                    return redirect(url_for("analyze_with_selection"))
                
                # LIMIT THE NUMBER OF URLS FOR PERFORMANCE
                total_found = len(all_urls)
                if total_found > MAX_URLS_TO_STORE:
                    print(f"Found {total_found:,} URLs. Limiting to {MAX_URLS_TO_STORE:,} for storage.")
                    
                    # For very large sites, offer sampling option
                    if total_found > 100000:
                        flash(f"Found {total_found:,} URLs. This is a very large site. Limited to {MAX_URLS_TO_STORE:,} URLs for analysis.", "warning")
                    
                    all_urls = all_urls[:MAX_URLS_TO_STORE]
                else:
                    print(f"Found {total_found:,} URLs.")
                
                # Generate a unique session key for this analysis
                session_key = f"url_selection_{current_user.id}_{datetime.now().timestamp()}"
                
                # Store URLs in Redis - ensure data is properly serialized
                redis_data = {
                    'urls': all_urls,
                    'sitemap_url': sitemap_url,
                    'original_url': url,
                    'total_count': len(all_urls),
                    'original_total_count': total_found
                }
                
                # DEBUG: Print first few URLs to verify
                print(f"DEBUG: First 3 URLs to store: {all_urls[:3]}")
                print(f"DEBUG: Total URLs to store: {len(all_urls)}")
                
                # Store in Redis with proper error handling
                try:
                    redis_conn.setex(
                        f"sitemap_urls:{session_key}", 
                        3600,  # Expire in 1 hour
                        json.dumps(redis_data)
                    )
                    print(f"DEBUG: Successfully stored data in Redis with key: sitemap_urls:{session_key}")
                except Exception as redis_error:
                    print(f"DEBUG: Redis storage error: {str(redis_error)}")
                    # Try with smaller chunk if Redis fails
                    if len(all_urls) > 5000:
                        print("DEBUG: Trying with smaller chunk (5000 URLs)")
                        redis_data['urls'] = all_urls[:5000]
                        redis_data['total_count'] = 5000
                        redis_conn.setex(
                            f"sitemap_urls:{session_key}", 
                            3600,
                            json.dumps(redis_data)
                        )
                    else:
                        raise redis_error
                
                # Store only the key in session (small size)
                session['url_selection_key'] = session_key
                session['display_count'] = min(MAX_URLS_TO_DISPLAY, len(all_urls))
                session['total_url_count'] = len(all_urls)
                
                # For UI, show only first MAX_URLS_TO_DISPLAY URLs for selection
                display_urls = all_urls[:MAX_URLS_TO_DISPLAY]
                
                flash(f"Found {total_found:,} URLs. Showing first {len(display_urls)} for selection. You can analyze up to {len(all_urls):,} URLs.", "info")
                
                return render_template("url_selection.html",
                                     form=form,
                                     selection_form=url_selection_form,
                                     url_count=len(display_urls),
                                     total_url_count=len(all_urls),
                                     urls=display_urls)
            
            except Exception as e:
                flash(f"Error: {str(e)}", "danger")
                return redirect(url_for("analyze_with_selection"))
        else:
            flash("Please enter a valid URL.", "danger")
    
    # Clear session data on GET request
    if request.method == "GET":
        session.pop('url_selection_key', None)
        session.pop('display_count', None)
        session.pop('total_url_count', None)
    
    return render_template("url_selection.html",
                         form=form,
                         selection_form=url_selection_form,
                         url_count=0,
                         total_url_count=0,
                         urls=[])

@app.route("/analyze_selected", methods=["POST"])
@login_required
def analyze_selected():
    ""Process user-selected URLs for analysis""
    try:
        # Get selected URLs from form
        selected_urls = request.form.getlist('selected_urls')
        select_all = request.form.get('select_all') == 'on'
        
        # Get the session key for stored URLs
        session_key = session.get('url_selection_key')
        
        if not session_key:
            flash("Session expired. Please start over.", "danger")
            return redirect(url_for("analyze_with_selection"))
        
        # Get stored URLs from Redis
        redis_data = redis_conn.get(f"sitemap_urls:{session_key}")
        if not redis_data:
            flash("URL data expired. Please start over.", "danger")
            return redirect(url_for("analyze_with_selection"))
        
        data = json.loads(redis_data)
        all_urls = data.get('urls', [])
        sitemap_url = data.get('sitemap_url', '')
        original_url = data.get('original_url', '')
        
        if not all_urls:
            flash("No URLs available for selection.", "danger")
            return redirect(url_for("analyze_with_selection"))
        
        # Determine which URLs to analyze
        if select_all:
            # When "Select All" is checked, analyze ALL URLs
            urls_to_analyze = all_urls
            print(f"Select All: Analyzing ALL {len(urls_to_analyze)} URLs")
        elif selected_urls:
            # User manually selected URLs
            urls_to_analyze = selected_urls
            print(f"Selected URLs: Analyzing {len(urls_to_analyze)} URLs")
        else:
            print("No URLs selected and select_all is False")
            flash("Please select at least one URL to analyze.", "warning")
            return redirect(url_for("analyze_with_selection"))
        
        if not urls_to_analyze:
            print("urls_to_analyze is empty")
            flash("No URLs selected for analysis.", "warning")
            return redirect(url_for("analyze_with_selection"))
        
        print(f"First 3 URLs to analyze: {urls_to_analyze[:3]}")
        
        # Check user plan and limits
        user_plan = UserPlan.query.filter_by(user_id=current_user.id)\
                                .order_by(UserPlan.start_date.desc())\
                                .first()
        
        if not user_plan:
            flash("Plan required. Please select a plan first.", "warning")
            return redirect(url_for("select_plan"))
        
        # Check if plan has expired
        if user_plan.plan.duration:
            end_date = user_plan.start_date + timedelta(days=user_plan.plan.duration * 30)
            if datetime.utcnow() > end_date:
                flash("Your plan has expired. Please upgrade to continue using the service.", "warning")
                return redirect(url_for("select_plan"))
        
        url_usage = UserUrlUsage.query.filter_by(user_id=current_user.id).first()
        analyzed_urls_count = url_usage.urls_used if url_usage else 0
        
        # Check if user can analyze this many URLs
        if analyzed_urls_count + len(urls_to_analyze) > user_plan.plan.max_urls:
            available = user_plan.plan.max_urls - analyzed_urls_count
            # If selecting all, offer to analyze just up to available limit
            if select_all and len(all_urls) > available:
                urls_to_analyze = all_urls[:available]
                flash(f"You can only analyze {available} more URLs. Analyzing first {available} URLs.", "info")
            else:
                flash(f"You can only analyze {available} more URLs with your current plan. You selected {len(urls_to_analyze)} URLs.", "warning")
                return redirect(url_for("analyze_with_selection"))
        
        # Create analysis job
        job = AnalysisJob(
            id=str(uuid.uuid4()),
            user_id=current_user.id,
            website_url=original_url,
            status="queued",
            progress=0,
            message=f"Preparing to analyze {len(urls_to_analyze)} selected URLs"
        )
        db.session.add(job)
        db.session.commit()
        
        # Store selected URLs in Redis for the task
        redis_conn.setex(f"selected_urls:{job.id}", 86400,  # 24 hours
                       json.dumps({
                           'urls': urls_to_analyze,
                           'sitemap_url': sitemap_url,
                           'original_url': original_url,
                           'count': len(urls_to_analyze)
                       }))
        
        # Start background task with job ID
        try:
            from tasks import analyze_selected_urls_task
            task = analyze_selected_urls_task.send(
                current_user.id,
                job.id,
                user_plan.plan.max_urls,
                analyzed_urls_count
            )
            
            # Update job with task_id
            job.task_id = task.message_id
            db.session.commit()
            
            flash(f"Started analysis of {len(urls_to_analyze)} selected URLs.", "success")
            
            # Clear the session data
            session.pop('url_selection_key', None)
            session.pop('display_count', None)
            session.pop('total_url_count', None)
            
            # Redirect to dashboard with job_id parameter
            return redirect(url_for("dashboard", 
                                  username=current_user.email,
                                  job_id=job.id))
            
        except ImportError as e:
            flash("Background processing unavailable. Please try again later.", "danger")
            return redirect(url_for("analyze_with_selection"))
        
    except Exception as e:
        app.logger.error(f"Error in analyze_selected: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("analyze_with_selection"))"""
"""@app.route("/analyze_selected", methods=["POST"])
@login_required
def analyze_selected():
    ""Process user-selected URLs for analysis""
    try:
        # Get selected URLs from form
        selected_urls = request.form.getlist('selected_urls')
        original_url = request.form.get('original_url', '')
        
        # Check if it's an AJAX request
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        if not selected_urls:
            if is_ajax:
                return jsonify({"success": False, "message": "No URLs selected"}), 400
            flash("Please select at least one URL to analyze.", "warning")
            return redirect(url_for("analyze_with_selection"))
        
        # Check user plan and limits (your existing code)
        user_plan = UserPlan.query.filter_by(user_id=current_user.id)\
                                .order_by(UserPlan.start_date.desc())\
                                .first()
        
        if not user_plan:
            if is_ajax:
                return jsonify({"success": False, "message": "Plan required"}), 402
            flash("Plan required. Please select a plan first.", "warning")
            return redirect(url_for("select_plan"))
        
        url_usage = UserUrlUsage.query.filter_by(user_id=current_user.id).first()
        analyzed_urls_count = url_usage.urls_used if url_usage else 0
        
        # Check if user can analyze this many URLs
        if analyzed_urls_count + len(selected_urls) > user_plan.plan.max_urls:
            available = user_plan.plan.max_urls - analyzed_urls_count
            if is_ajax:
                return jsonify({
                    "success": False,
                    "message": f"You can only analyze {available} more URLs with your current plan."
                }), 403
            flash(f"You can only analyze {available} more URLs with your current plan.", "warning")
            return redirect(url_for("analyze_with_selection"))
        
        # Create analysis job
        job = AnalysisJob(
            id=str(uuid.uuid4()),
            user_id=current_user.id,
            website_url=original_url,
            status="queued",
            progress=0,
            message=f"Preparing to analyze {len(selected_urls)} selected URLs"
        )
        db.session.add(job)
        db.session.commit()
        
        # Store selected URLs in Redis for the task
        redis_conn.setex(f"selected_urls:{job.id}", 86400,  # 24 hours
                       json.dumps({
                           'urls': selected_urls,
                           'original_url': original_url,
                           'count': len(selected_urls)
                       }))
        
        #CRITICAL: Store initial job data in Redis for SSE endpoint
        redis_conn.setex(f"selected_urls_job:{job.id}", 3600, json.dumps({
            "status": "queued",
            "progress": 0,
            "message": f"Starting analysis of {len(selected_urls)} URLs...",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "user_id": current_user.id,
            "job_id": job.id,
            "url_count": len(selected_urls),
            "original_url": original_url
        }))
        
        # Start background task with job ID
        try:
            from tasks import analyze_selected_urls_task
            task = analyze_selected_urls_task.send(
                current_user.id,
                job.id,
                user_plan.plan.max_urls,
                analyzed_urls_count
            )
            
            # Update job with task_id
            job.task_id = task.message_id
            db.session.commit()
            
            
            return jsonify({
                    "success": True,
                    "message": f"Started analysis of {len(selected_urls)} selected URLs.",
                    "job_id": job.id,
                    "redirect": url_for("dashboard", username=current_user.email, job_id=job.id)
                })
            
            flash(f"Started analysis of {len(selected_urls)} selected URLs.", "success")
            return redirect(url_for("dashboard", username=current_user.email, job_id=job.id))
            
        except ImportError as e:
            
            return jsonify({"success": False, "message": "Background processing unavailable"}), 500
            flash("Background processing unavailable. Please try again later.", "danger")
            return redirect(url_for("analyze_with_selection"))
        
    except Exception as e:
        app.logger.error(f"Error in analyze_selected: {str(e)}")
        import traceback
        traceback.print_exc()
        
        
        return jsonify({"success": False, "message": str(e)}), 500
        
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("analyze_with_selection"))"""
@app.route("/analyze_selected", methods=["POST"])
@login_required
def analyze_selected():
    """Process user-selected URLs for analysis"""
    try:
        # Get selected URLs from form
        selected_urls = request.form.getlist('selected_urls')
        original_url = request.form.get('original_url', '')
        
        # Check if it's an AJAX request
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        if not selected_urls:
            if is_ajax:
                return jsonify({"success": False, "message": "No URLs selected"}), 400
            flash("Please select at least one URL to analyze.", "warning")
            return redirect(url_for("analyze_with_selection"))
        
        # Check user plan and limits
        user_plan = UserPlan.query.filter_by(user_id=current_user.id)\
                                .order_by(UserPlan.start_date.desc())\
                                .first()
        
        if not user_plan:
            if is_ajax:
                return jsonify({"success": False, "message": "Plan required"}), 402
            flash("Plan required. Please select a plan first.", "warning")
            return redirect(url_for("select_plan"))
        
        # ========== PLAN EXPIRATION CHECK ==========
        plan_expired = False
        if user_plan.plan.duration:
            end_date = user_plan.start_date + timedelta(days=user_plan.plan.duration * 30)
            if datetime.utcnow() > end_date:
                plan_expired = True
        
        if plan_expired:
            if is_ajax:
                return jsonify({
                    "success": False, 
                    "message": "Your plan has expired. Please upgrade to continue using the service.",
                    "redirect": url_for("select_plan")
                }), 403
            flash("Your plan has expired. Please upgrade to continue using the service.", "warning")
            return redirect(url_for("select_plan"))
        # ========== END PLAN EXPIRATION CHECK ==========
        
        # Check URL usage
        url_usage = UserUrlUsage.query.filter_by(user_id=current_user.id).first()
        analyzed_urls_count = url_usage.urls_used if url_usage else 0
        
        # Check if user can analyze this many URLs
        if analyzed_urls_count + len(selected_urls) > user_plan.plan.max_urls:
            available = user_plan.plan.max_urls - analyzed_urls_count
            if is_ajax:
                return jsonify({
                    "success": False,
                    "message": f"You can only analyze {available} more URLs with your current plan."
                }), 403
            flash(f"You can only analyze {available} more URLs with your current plan.", "warning")
            return redirect(url_for("analyze_with_selection"))
        
        # Create analysis job
        job = AnalysisJob(
            id=str(uuid.uuid4()),
            user_id=current_user.id,
            website_url=original_url,
            status="queued",
            progress=0,
            message=f"Preparing to analyze {len(selected_urls)} selected URLs"
        )
        db.session.add(job)
        db.session.commit()
        
        # Store selected URLs in Redis for the task
        redis_conn.setex(f"selected_urls:{job.id}", 86400,  # 24 hours
                       json.dumps({
                           'urls': selected_urls,
                           'original_url': original_url,
                           'count': len(selected_urls)
                       }))
        
        # Store initial job data in Redis for SSE endpoint
        redis_conn.setex(f"selected_urls_job:{job.id}", 3600, json.dumps({
            "status": "queued",
            "progress": 0,
            "message": f"Starting analysis of {len(selected_urls)} URLs...",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "user_id": current_user.id,
            "job_id": job.id,
            "url_count": len(selected_urls),
            "original_url": original_url
        }))
        
        # Start background task with job ID
        try:
            from tasks import analyze_selected_urls_task
            task = analyze_selected_urls_task.send(
                current_user.id,
                job.id,
                user_plan.plan.max_urls,
                analyzed_urls_count
            )
            
            # Update job with task_id
            job.task_id = task.message_id
            db.session.commit()
            
            if is_ajax:
                return jsonify({
                    "success": True,
                    "message": f"Started analysis of {len(selected_urls)} selected URLs.",
                    "job_id": job.id,
                    "redirect": url_for("dashboard", username=current_user.email, job_id=job.id)
                })
            else:
                flash(f"Started analysis of {len(selected_urls)} selected URLs.", "success")
                return redirect(url_for("dashboard", username=current_user.email, job_id=job.id))
            
        except ImportError as e:
            if is_ajax:
                return jsonify({"success": False, "message": "Background processing unavailable"}), 500
            flash("Background processing unavailable. Please try again later.", "danger")
            return redirect(url_for("analyze_with_selection"))
        
    except Exception as e:
        app.logger.error(f"Error in analyze_selected: {str(e)}")
        import traceback
        traceback.print_exc()
        
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if is_ajax:
            return jsonify({"success": False, "message": str(e)}), 500
        else:
            flash(f"Error: {str(e)}", "danger")
            return redirect(url_for("analyze_with_selection"))

"""@app.route("/analyze_selected", methods=["POST"])
@login_required
def analyze_selected():
    try:
        # 1. Read data from form
        selected_urls = request.form.getlist("selected_urls")
        original_url = request.form.get("original_url", "").strip()

        if not selected_urls:
            return jsonify({
                "success": False,
                "message": "No URLs selected"
            }), 400

        # 2. Check user plan
        user_plan = UserPlan.query.filter_by(user_id=current_user.id)\
                                  .order_by(UserPlan.start_date.desc())\
                                  .first()

        if not user_plan:
            return jsonify({
                "success": False,
                "message": "Plan required"
            }), 402

        url_usage = UserUrlUsage.query.filter_by(user_id=current_user.id).first()
        analyzed_urls_count = url_usage.urls_used if url_usage else 0

        if analyzed_urls_count + len(selected_urls) > user_plan.plan.max_urls:
            available = user_plan.plan.max_urls - analyzed_urls_count
            return jsonify({
                "success": False,
                "message": f"You can analyze only {available} more URLs"
            }), 403

        # 3. Create Analysis Job
        job = AnalysisJob(
            id=str(uuid.uuid4()),
            user_id=current_user.id,
            website_url=original_url,
            status="queued",
            progress=0,
            message=f"Preparing to analyze {len(selected_urls)} URLs"
        )
        db.session.add(job)
        db.session.commit()

        # 4. Store selected URLs in Redis
        redis_conn.setex(
            f"selected_urls:{job.id}",
            86400,
            json.dumps({
                "urls": selected_urls,
                "original_url": original_url,
                "count": len(selected_urls)
            })
        )

        # 5. Start background task
        from tasks import analyze_selected_urls_task

        task = analyze_selected_urls_task.send(
            current_user.id,
            job.id,
            user_plan.plan.max_urls,
            analyzed_urls_count
        )

        job.task_id = task.message_id
        db.session.commit()

        # ✅ 6. THIS IS THE IMPORTANT PART
        return jsonify({
            "success": True,
            "job_id": job.id
        })

    except Exception as e:
        app.logger.error(f"analyze_selected error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Failed to start selected URL analysis"
        }), 500"""


@app.route('/selected_urls_progress')
@login_required
def selected_urls_progress():
    """SSE endpoint for selected URLs analysis progress"""
    job_id = request.args.get("job_id")

    def generate():
        last_progress = 0
        last_message = ""
        with app.app_context():
            while True:
                try:
                    # Try to get job data from Redis first
                    redis_key = f"selected_urls_job:{job_id}"
                    job_data = redis_conn.get(redis_key)
                    
                    if job_data:
                        job_data = json.loads(job_data)
                    else:
                        # Fallback to database if Redis data not found
                        job = AnalysisJob.query.get(job_id)
                        if not job:
                            yield f"data: {json.dumps({'error': 'Job not found', 'status': 'failed'})}\n\n"
                            break
                        
                        job_data = {
                            "status": job.status,
                            "progress": job.progress or 0,
                            "message": job.message or "Processing...",
                            "updated_at": job.started_at.isoformat() if job.started_at else datetime.utcnow().isoformat()
                        }
                    
                    # Only send update if something changed
                    current_progress = job_data.get("progress", 0)
                    current_message = job_data.get("message", "")
                    
                    if (current_progress != last_progress or 
                        current_message != last_message or 
                        job_data.get("status") != "processing"):
                        
                        data = {
                            "status": job_data.get("status", "processing"),
                            "progress": int(current_progress),
                            "message": current_message,
                        }
                        
                        # Extract current URL from message for display
                        message = data["message"]
                        if message and "Analyzing URL" in message:
                            try:
                                # Extract URL from message pattern "Analyzing URL X of Y: URL"
                                url_match = re.search(r'Analyzing URL \d+ of \d+: (.+)$', message)
                                if url_match:
                                    url = url_match.group(1)
                                    if len(url) > 100:
                                        url = url[:97] + "..."
                                    data["current_url"] = url
                            except Exception as e:
                                print(f"Error extracting URL: {e}")
                        
                        # Add download URL if available
                        if job_data.get("download_url"):
                            data["download_url"] = job_data.get("download_url")
                        
                        yield f"data: {json.dumps(data)}\n\n"
                        
                        last_progress = current_progress
                        last_message = current_message
                    
                    # Check if job is finished
                    if job_data.get("status") in ["completed", "failed", "canceled"]:
                        if job_data.get("status") == "completed":
                            # Add extra completion message
                            yield f"data: {json.dumps({'status': 'completed', 'progress': 100, 'message': 'Analysis complete! Download ready.'})}\n\n"
                        break
                    
                except Exception as e:
                    print(f"SSE error: {e}")
                    yield f"data: {json.dumps({'error': f'SSE error: {str(e)}', 'status': 'failed'})}\n\n"
                    break
                
                time.sleep(1)  # Check every second
    
    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/check_selected_job', methods=['GET'])
@login_required
def check_selected_job():
    """Check selected URL analysis job progress"""
    job_id = request.args.get('job_id')
    if not job_id:
        return jsonify({"error": "Missing job_id"}), 400
    
    try:
        job = AnalysisJob.query.get(job_id)
        if not job or job.user_id != current_user.id:
            return jsonify({"error": "Invalid job"}), 404
        
        return jsonify({
            "status": job.status,
            "progress": job.progress,
            "message": job.message,
            "download_url": url_for("download", analysis_id=job.analysis_id) if job.analysis_id else None
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/cancel_selected_analysis', methods=['POST'])
@login_required
def cancel_selected_analysis():
    """Cancel selected URL analysis"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request"}), 400
        
    job_id = data.get("job_id")
    if not job_id:
        return jsonify({"error": "Missing job_id"}), 400

    # Verify job belongs to current user
    job = AnalysisJob.query.filter_by(id=job_id, user_id=current_user.id).first()
    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job.status in ["completed", "failed", "canceled"]:
        return jsonify({"error": "Analysis already completed"}), 400

    # Mark job as canceled in DB
    job.status = "canceled"
    job.message = "Canceled by user"
    job.completed_at = datetime.utcnow()
    db.session.commit()

    # Set cancel flag in Redis
    try:
        redis_conn.set(f"cancel_selected_job:{job_id}", "1", ex=3600)
        return jsonify({"success": True, "message": "Cancellation requested"})
    except Exception as e:
        app.logger.error(f"Redis error: {str(e)}")
        return jsonify({"error": "Failed to process cancellation"}), 500

@app.route('/selected_urls_results/<job_id>')
@login_required
def selected_urls_results(job_id):
    """Display results for selected URLs analysis"""
    # Get the job
    job = AnalysisJob.query.filter_by(id=job_id, user_id=current_user.id).first()
    if not job:
        flash("Analysis job not found.", "danger")
        return redirect(url_for('dashboard', username=current_user.email))
    
    # Get the analysis
    analysis = Analysis.query.get(job.analysis_id)
    if not analysis:
        flash("Analysis results not found.", "danger")
        return redirect(url_for('dashboard', username=current_user.email))
    
    # Get metrics summary
    metrics = analysis.metrics or {}
    moz_metrics = analysis.moz_metrics or {}
    
    # Calculate some summary statistics
    urls_analyzed = len(metrics.get('URL', []))
    
    # Calculate average scores
    desktop_scores = [float(score) for score in metrics.get('Performance Score (Desktop)', []) 
                     if isinstance(score, (int, float)) or (isinstance(score, str) and score.replace('.', '').isdigit())]
    mobile_scores = [float(score) for score in metrics.get('Performance Score (Mobile)', []) 
                    if isinstance(score, (int, float)) or (isinstance(score, str) and score.replace('.', '').isdigit())]
    
    avg_desktop = sum(desktop_scores) / len(desktop_scores) if desktop_scores else 0
    avg_mobile = sum(mobile_scores) / len(mobile_scores) if mobile_scores else 0
    
    # Count issues
    missing_titles = sum(1 for title in metrics.get('Meta Title', []) 
                        if not title or title == 'N/A')
    missing_descriptions = sum(1 for desc in metrics.get('Meta Description', []) 
                              if not desc or desc == 'N/A')
    
    return render_template('selected_urls_results.html',
                         job=job,
                         analysis=analysis,
                         metrics=metrics,
                         moz_metrics=moz_metrics,
                         urls_analyzed=urls_analyzed,
                         avg_desktop=round(avg_desktop, 1),
                         avg_mobile=round(avg_mobile, 1),
                         missing_titles=missing_titles,
                         missing_descriptions=missing_descriptions,
                         grade=analysis.grade)

@app.route('/delete_analysis', methods=['POST'])
@login_required
def delete_analysis():
    data = request.get_json()
    analysis_id = data.get('analysis_id')

    analysis = Analysis.query.filter_by(
        id=analysis_id,
        user_id=current_user.id
    ).first()

    if not analysis:
        return jsonify({'success': False, 'error': 'Report not found'}), 404

    # Delete excel file
    if analysis.excel_file and os.path.exists(analysis.excel_file):
        try:
            os.remove(analysis.excel_file)
        except Exception as e:
            print("File delete error:", e)

    db.session.delete(analysis)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/delete_analysis_bulk', methods=['POST'])
@login_required
def delete_analysis_bulk():
    data = request.get_json()
    analysis_ids = data.get('analysis_ids', [])

    deleted = 0
    for analysis_id in analysis_ids:
        analysis = Analysis.query.filter_by(
            id=analysis_id,
            user_id=current_user.id
        ).first()

        if analysis:
            if analysis.excel_file and os.path.exists(analysis.excel_file):
                try:
                    os.remove(analysis.excel_file)
                except Exception:
                    pass

            db.session.delete(analysis)
            deleted += 1

    db.session.commit()

    return jsonify({
        'success': True,
        'deleted_count': deleted
    })

@app.route('/check-session')
def check_session():
    """Simple session check"""
    if current_user.is_authenticated:
        return jsonify({'authenticated': True})
    return jsonify({'authenticated': False}), 401

@app.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    form = AnalysisForm()
    
    if form.validate_on_submit():
        try:
            if "user" not in session or session["user"] != current_user.email:
                return jsonify({"success": False, "message": "Unauthorized"}), 401

            user_plan = UserPlan.query.filter_by(user_id=current_user.id)\
                                    .order_by(UserPlan.start_date.desc())\
                                    .first()
            if not user_plan:
                return jsonify({"success": False, "message": "Plan required"}), 402

            # Check if plan has expired (remaining days <= 0)
            if user_plan.plan.duration:
                end_date = user_plan.start_date + timedelta(days=user_plan.plan.duration * 30)
                if datetime.utcnow() > end_date:
                    return jsonify({
                        "success": False,
                        "message": "Your plan has expired. Please upgrade to continue using the service.",
                        "redirect": url_for("select_plan")
                    }), 403

            url_usage = UserUrlUsage.query.filter_by(user_id=current_user.id).first()
            analyzed_urls_count = url_usage.urls_used if url_usage else 0
            
            if analyzed_urls_count >= user_plan.plan.max_urls:
                return jsonify({
                    "success": False,
                    "message": f"URL limit reached ({user_plan.plan.max_urls})"
                }), 403

            url = form.url.data.strip()
            if not is_valid_url(url):
                return jsonify({"success": False, "message": "Invalid URL"}), 400

            # Create analysis job record
            job = AnalysisJob(
                id=str(uuid.uuid4()),
                user_id=current_user.id,
                website_url=url,
                status="queued",
                progress=0
            )
            db.session.add(job)
            db.session.commit()

            # IMPORTANT: Lazy import inside the route to avoid circular imports
            try:
                # Dynamically import the task module
                from tasks import analyze_sitemap_task
                
                # Start task with job ID
                task = analyze_sitemap_task.send(
                    current_user.id,
                    url,
                    user_plan.plan.max_urls,
                    analyzed_urls_count,
                    job.id
                )
                
                # Update job with task_id
                job.task_id = task.message_id
                db.session.commit()
                
                return jsonify({
                    "success": True,
                    "message": "Analysis started",
                    "task_id": task.message_id,
                    "job_id": job.id
                })
                
            except ImportError as e:
                app.logger.error(f"Failed to import task module: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Background processing unavailable. Please try again later."
                }), 500
                
            except Exception as e:
                app.logger.error(f"Task submission error: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": f"Failed to start analysis: {str(e)}"
                }), 500
            
        except Exception as e:
            app.logger.error(f"Analysis error: {str(e)}")
            return jsonify({
                "success": False,
                "message": "Internal error"
            }), 500

    return render_template("dashboard.html", form=form, username=current_user.username)


@app.route('/check_dramatiq_task', methods=['GET'])
@login_required
def check_dramatiq_task():
    job_id = request.args.get('job_id')
    if not job_id:
        return jsonify({"error": "Missing job_id"}), 400
    
    try:
        job = AnalysisJob.query.get(job_id)
        if not job or job.user_id != current_user.id:
            return jsonify({"error": "Invalid job"}), 404
        
        # Check if we have a task_id to check with Dramatiq
        if job.task_id:
            try:
                from tasks import analyze_sitemap_task
                result = analyze_sitemap_task.get_result(job.task_id, block=False)
                
                if result:
                    # Update job status based on Dramatiq result
                    if 'error' in result:
                        job.status = "failed"
                        job.message = result['error']
                    else:
                        job.status = "completed"
                        job.analysis_id = result.get('analysis_id')
                        job.progress = 100
                    job.completed_at = datetime.utcnow()
                    db.session.commit()
            except Exception as e:
                app.logger.error(f"Error checking task result: {str(e)}")
        
        return jsonify({
            "status": job.status,
            "progress": job.progress,
            "message": job.message,
            "download_url": url_for("download", analysis_id=job.analysis_id) if job.analysis_id else None
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/cancel_analysis", methods=["POST"])
@login_required
@csrf.exempt  # Only if you're having CSRF issues with AJAX
def cancel_analysis():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request"}), 400
        
    job_id = data.get("job_id")
    if not job_id:
        return jsonify({"error": "Missing job_id"}), 400

    # Verify job belongs to current user
    job = AnalysisJob.query.filter_by(id=job_id, user_id=current_user.id).first()
    if not job:
        return jsonify({"error": "Job not found"}), 404

    if job.status in ["completed", "failed", "canceled"]:
        return jsonify({"error": "Analysis already completed"}), 400

    # Mark job as canceled in DB
    job.status = "canceled"
    job.message = "Canceled by user"
    job.completed_at = datetime.utcnow()
    db.session.commit()

    # Set cancel flag in Redis
    try:
        redis_conn.set(f"cancel_job:{job_id}", "1", ex=3600)  # Expire after 1 hour
        return jsonify({"success": True, "message": "Cancellation requested"})
    except Exception as e:
        app.logger.error(f"Redis error: {str(e)}")
        return jsonify({"error": "Failed to process cancellation"}), 500


"""@app.route('/dramatiq_progress')
@login_required
def dramatiq_progress():
    job_id = request.args.get("job_id")

    def generate():
        while True:
            with app.app_context():
                job = AnalysisJob.query.filter_by(id=job_id).first()
                if not job:
                    yield f"data: {json.dumps({'error': 'Job not found'})}\n\n"
                    break

                data = {
                    "progress": int(job.progress or 0),
                    "message": job.message or "Processing...",
                    "status": job.status
                }

                yield f"data: {json.dumps(data)}\n\n"

                if job.status in ["completed", "failed", "canceled"]:
                    break

            time.sleep(2)

    return Response(generate(), mimetype="text/event-stream")"""

@app.route('/dramatiq_progress')
@login_required
def dramatiq_progress():
    job_id = request.args.get("job_id")

    def generate():
        last_job_check = time.time()
        while True:
            with app.app_context():
                # Check job status no more than once per second
                if time.time() - last_job_check >= 1:
                    job = AnalysisJob.query.filter_by(id=job_id).first()
                    if not job:
                        yield f"data: {json.dumps({'error': 'Job not found'})}\n\n"
                        break

                    # Safely handle None message
                    message = job.message or "Processing..."
                    data = {
                        "progress": int(job.progress or 0),
                        "message": message,
                        "status": job.status or "unknown"
                    }

                    # Safely extract current URL if available
                    if message and "Analyzing URL" in message:
                        try:
                            url_part = message.split("Analyzing URL")[-1]
                            if ":" in url_part:
                                data["current_url"] = url_part.split(":")[-1].strip()
                        except Exception:
                            pass

                    yield f"data: {json.dumps(data)}\n\n"
                    last_job_check = time.time()

                    if job.status in ["completed", "failed", "canceled"]:
                        if job.status == "completed" and job.analysis_id:
                            data["download_url"] = url_for("download", analysis_id=job.analysis_id)
                            yield f"data: {json.dumps(data)}\n\n"
                        break

            time.sleep(0.5)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


if __name__ == "__main__":
    app.run(debug=True, port=5037)
