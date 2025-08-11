from flask import Flask, render_template, request, redirect, url_for, flash, render_template_string, send_file, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import os
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
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
import time
import ssl
import socket
from datetime import datetime

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
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Change if using another SMTP service
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  # Replace with your email
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # Replace with app-specific password if using Gmail
app.config['MAIL_DEFAULT_SENDER'] = 'support@magnustic.com'
app.config['SESSION_COOKIE_MAX_SIZE'] = 4000

mail = Mail(app)

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
    user = db.relationship('User', backref='user_plans')  # Removed backref here
    plan = db.relationship('Plan', backref='user_plans')  # Removed backref here

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
    analyses = db.relationship('Analysis', backref='user', lazy=True)

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

class AnalysisJob(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # UUID as string
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='queued')  # queued, processing, completed, failed
    progress = db.Column(db.Integer, default=0)
    message = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis.id'), nullable=True)
    task_id = db.Column(db.String(50), nullable=True)  # Add this line for Dramatiq task ID
    
    user = db.relationship('User', backref='analysis_jobs')
    analysis = db.relationship('Analysis', backref='job')

class UserUrlUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    urls_used = db.Column(db.Integer, default=0)

    user = db.relationship('User', backref='url_usage')


# Near your other form classes (RegistrationForm, LoginForm)
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
def fetch_html(url):
    """Fetch HTML content of a given URL."""
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None
    
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
        print(f"Error fetching URLs from sitemap {sitemap_url}: {e}")
        return []

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
    
def analyze_page(url):
    """Analyze a single web page for SEO parameters, including broken links and image details."""
    html_content = fetch_html(url)
    if not html_content:
        return None

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        response_code = response.status_code
        html_content = response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        try:
            response_code = requests.head(url, timeout=5).status_code
        except:
            response_code = "Error"
        return None
    
    soup = BeautifulSoup(html_content, "lxml")

    robots_meta = soup.find("meta", attrs={"name": "robots"})
    indexability = "Noindex" if robots_meta and "noindex" in robots_meta.get("content", "").lower() else "Indexable"

    # Meta information
    meta_title = soup.title.string.strip() if soup.title else "N/A"
    meta_title_char_count = len(meta_title) if meta_title != "N/A" else 0

    meta_description_tag = soup.find("meta", attrs={"name": "description"})
    meta_description = (
        meta_description_tag["content"].strip()
        if meta_description_tag and meta_description_tag.get("content")
        else "N/A"
    )
    meta_description_char_count = len(meta_description) if meta_description != "N/A" else 0

    body_text = soup.get_text()
    word_count = len(body_text.split())

    # Headers
    h1_tags = [tag.get_text(strip=True) for tag in soup.find_all("h1")]
    h2_tags = [tag.get_text(strip=True) for tag in soup.find_all("h2")]

    # Canonical tag
    canonical_tag = soup.find("link", attrs={"rel": "canonical"})
    canonical_url = canonical_tag["href"].strip() if canonical_tag else "N/A"

    # Structured data
    structured_data = "Yes" if soup.find("script", attrs={"type": "application/ld+json"}) else "No"

    # Images
    images = soup.find_all("img")
    image_details = []
    largest_image = None
    largest_image_size = 0

    for img in images:
        src = img.get("src")
        alt = img.get("alt", "N/A")
        if not src:
            continue
        src = urljoin(url, src)
        try:
            response = requests.get(src, stream=True, headers=headers)
            response.raise_for_status()
            size = int(response.headers.get("Content-Length", 0))
            image_details.append({
                "Image URL": src,
                "Alt Tag": alt,
                "Image Size (KB)": f"{size / 1024:.2f} KB"
            })
            if size > largest_image_size:
                largest_image_size = size
                largest_image = src
        except Exception:
            continue

    # Convert bytes to kilobytes with 2 decimal places
    largest_image_size_kb = f"{largest_image_size / 1024:.2f} KB" if largest_image_size > 0 else "N/A"

    # Links
    internal_links = [a["href"] for a in soup.find_all("a", href=True) if urlparse(a["href"]).netloc == urlparse(url).netloc]
    external_links = [a["href"] for a in soup.find_all("a", href=True) if urlparse(a["href"]).netloc != urlparse(url).netloc]

    # Detect broken links
    broken_links = []
    for link in soup.find_all("a", href=True):
        href = urljoin(url, link["href"])
        try:
            response = requests.head(href, timeout=5)
            if response.status_code >= 400:  # Check for HTTP errors
                broken_links.append(href)
        except Exception:
            broken_links.append(href)

    broken_links_str = "\n".join(broken_links) if broken_links else "N/A"

    email_issues = check_email_privacy(html_content)

    flash_used = any(tag for tag in soup.find_all(['object', 'embed']) if '.swf' in str(tag))
    iframes_used = bool(soup.find_all('iframe'))
    favicon_used = bool(
        soup.find('link', rel=lambda val: val and 'icon' in val.lower()) or
        soup.find('link', href=lambda val: val and 'favicon' in val.lower())
    )

    return {
        "Meta Title": meta_title,
        "Meta Title Character Count": meta_title_char_count,
        "Meta Description": meta_description,
        "Meta Description Character Count": meta_description_char_count,
        "Word Count": word_count,
        "H1 Tags": ", ".join(h1_tags) if h1_tags else "N/A",
        "H2 Tags": ", ".join(h2_tags) if h2_tags else "N/A",
        "Canonical Tag": canonical_url,
        "Largest Image Name": largest_image if largest_image else "N/A",
        "Largest Image Size (KB)": largest_image_size_kb,
        "Structured Data": structured_data,
        "Internal Links": len(internal_links),
        "External Links": len(external_links),
        "Broken Links": broken_links_str,
        "Image Details": image_details,
        "Indexability": indexability,
        "Response Code": response_code,
        "Email Privacy Issues": email_issues,
        "Flash Used": "Yes" if flash_used else "No",
        "iFrames Used": "Yes" if iframes_used else "No",
        "Favicon Used": "Yes" if favicon_used else "No"

    }

def fetch_pagespeed_metrics(url, strategy, api_key):
    """Fetch PageSpeed Insights metrics for a URL with specified strategy."""
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
        }

"""def guess_sitemap_url(base_url):
    ""Guess common sitemap locations and handle direct inputs.""
    print("Attempting to find the sitemap...")
    if base_url.endswith('.xml'):
        print(f"Using provided sitemap URL: {base_url}")
        return base_url

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
                return sitemap_url
        except Exception:
            continue
    return None"""

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
        return None

# Add this function to calculate grade
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


def generate_recommendations(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics):
    recs = []

    def is_missing(val):
        return not val or str(val).strip().lower() in ["n/a", "none", ""]

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
    """word_count = int(seo_metrics.get("Word Count", 0))
    if word_count < 500:
        recs.append("Content is too short. Add more text.")"""
    word_count = int(seo_metrics.get("Word Count", 0))
    if word_count < 1200:
        recs.append(f"Content is {word_count} words. The word Count Should be Atleast above 1200 to Rank High.")

    # Image size
    try:
        img_size = float(seo_metrics.get("Largest Image Size (KB)", "0").split()[0])
        if img_size > 300:
            recs.append("Largest image is too large. Compress it under 300KB.")
    except:
        pass

    # Links
    if int(seo_metrics.get("Internal Links", 0)) < 3:
        recs.append("No Internal Link Found. Please Add more internal links ForBetter Navigation Of Users.")
    if int(seo_metrics.get("External Links", 0)) < 1:
        recs.append("No external Link Found. Please Add external link to Increase Authority of page.")
    if not is_missing(seo_metrics.get("Broken Links")):
        recs.append("There Are broken Links That needs to be fixed For better Ranking")

    # PageSpeed (desktop and mobile)
    """if float(desktop_metrics.get("Performance Score", 100)) < 90:
        recs.append("Improve desktop performance (score < 90).")
    if float(mobile_metrics.get("Performance Score", 100)) < 90:
        recs.append("Improve mobile performance (score < 90).")"""
    desktop_score = float(desktop_metrics.get("Performance Score", 100))
    if desktop_score < 90:
        recs.append(f"Your Current Score is {desktop_score:.1f}/100. To Improve your Performance Read Our Blog")

    mobile_score = float(mobile_metrics.get("Performance Score", 100))
    if mobile_score < 90:
        recs.append(f"Your Current Score is {mobile_score:.1f}/100. To Improve your Performance Read Our Blog")

    def check_speed(metric, value, threshold, label):
        try:
            val = float(value.split()[0])
            if val > threshold:
                recs.append(f"{label} is high ({val}s). Aim for below {threshold}s.")
        except:
            pass


    """check_speed("LCP", desktop_metrics.get("LCP Lighthouse", "0"), 2.5, "Desktop LCP")
    check_speed("CLS", desktop_metrics.get("CLS Lighthouse", "0"), 0.1, "Desktop CLS")
    check_speed("LCP", mobile_metrics.get("LCP Lighthouse", "0"), 2.5, "Mobile LCP")
    check_speed("CLS", mobile_metrics.get("CLS Lighthouse", "0"), 0.1, "Mobile CLS")"""
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
    try:
        url = "https://status.search.google.com/products/rGHU1u87FJnkP6W2GwMi/history"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        # The dashboard lists incidents by year group
        rows = soup.select("tr")
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 2:
                title = cols[0].get_text(strip=True)
                date = cols[1].get_text(strip=True)
                if "core update" in title.lower() or "spam update" in title.lower():
                    return {
                        "title": title,
                        "published": date,
                        "summary": f"{title} began on {date}",
                        "link": url
                    }
        return None
    except Exception as e:
        print(f"Error fetching ranking history: {e}")
        return None

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
    desktop_perf = desktop_metrics.get('Performance Score', 0)
    mobile_perf = mobile_metrics.get('Performance Score', 0)
    if isinstance(desktop_perf, (int, float)) and isinstance(mobile_perf, (int, float)):
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
    if isinstance(desktop_perf, (int, float)):
        scores['usability'] += desktop_perf * 0.1

    # - Mobile performance (10%)
    if isinstance(mobile_perf, (int, float)):
        scores['usability'] += mobile_perf * 0.1

    # - Core Web Vitals (10%)
    # LCP (3%)
    lcp_desktop = float(desktop_metrics.get("LCP Lighthouse", "0").split()[0]) if isinstance(desktop_metrics.get("LCP Lighthouse"), str) else 0
    lcp_mobile = float(mobile_metrics.get("LCP Lighthouse", "0").split()[0]) if isinstance(mobile_metrics.get("LCP Lighthouse"), str) else 0
    avg_lcp = (lcp_desktop + lcp_mobile) / 2
    if avg_lcp <= 2.5:
        scores['usability'] += 3
    elif 2.5 < avg_lcp <= 4.0:
        scores['usability'] += 1.5
    else:
        scores['usability'] += 0

    # CLS (3%)
    cls_desktop = float(desktop_metrics.get("CLS Lighthouse", "0").split()[0]) if isinstance(desktop_metrics.get("CLS Lighthouse"), str) else 0
    cls_mobile = float(mobile_metrics.get("CLS Lighthouse", "0").split()[0]) if isinstance(mobile_metrics.get("CLS Lighthouse"), str) else 0
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

import tempfile
import os
import logging


import requests

def get_performance_metrics(url):
    try:
        response = requests.get("http://localhost:3001/metrics", params={"url": url}, timeout=200)
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

def capture_device_screenshots(url):
    try:
        res = requests.get("http://localhost:3002/screenshot", params={"url": url}, timeout=200)
        res.raise_for_status()
        data = res.json().get("screenshots", {})

        
        #base_url = "https://seoapp.magnustic.com"
        base_url = "http://localhost:3002"
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



"""def get_performance_metrics(url):
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1920,1080")  # Set viewport size

    try:
        logger.info("Initializing ChromeDriver...")
        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=options
        )

        # Navigate to URL and wait for page to load
        driver.get(url)
        time.sleep(5)  # Adjust based on your needs
        
        # Get performance timing
        timing = driver.execute_script("return window.performance.timing")
        navigation_start = timing['navigationStart']
        response_start = timing['responseStart']
        dom_complete = timing['domComplete']
        load_event_end = timing['loadEventEnd']
        
        # Calculate times in seconds
        server_response = (response_start - navigation_start) / 1000
        content_loaded = (dom_complete - navigation_start) / 1000
        scripts_complete = (load_event_end - navigation_start) / 1000
        
        # Get resource sizes and types with both transfer and decoded sizes
        resources = driver.execute_script(""
            var resources = window.performance.getEntriesByType('resource');
            return resources.map(function(r) {
                return {
                    name: r.name,
                    type: r.initiatorType,
                    transferSize: r.transferSize,  // compressed size
                    encodedBodySize: r.encodedBodySize,  // compressed size (alternative)
                    decodedBodySize: r.decodedBodySize   // uncompressed size
                };
            });
        "")
        
        # Initialize size trackers
        sizes = {
            'html': {'transfer': 0, 'decoded': 0},
            'css': {'transfer': 0, 'decoded': 0},
            'js': {'transfer': 0, 'decoded': 0},
            'images': {'transfer': 0, 'decoded': 0},
            'other': {'transfer': 0, 'decoded': 0}
        }
        
        for resource in resources:
            # Use transferSize if available, otherwise encodedBodySize
            transfer_size = resource.get('transferSize', resource.get('encodedBodySize', 0))
            decoded_size = resource.get('decodedBodySize', transfer_size)
            
            if resource['type'] == 'link' and ('css' in resource['name'] or '.css' in resource['name']):
                sizes['css']['transfer'] += transfer_size
                sizes['css']['decoded'] += decoded_size
            elif resource['type'] == 'script':
                sizes['js']['transfer'] += transfer_size
                sizes['js']['decoded'] += decoded_size
            elif resource['type'] == 'img':
                sizes['images']['transfer'] += transfer_size
                sizes['images']['decoded'] += decoded_size
            else:
                sizes['other']['transfer'] += transfer_size
                sizes['other']['decoded'] += decoded_size
        
        # Calculate HTML size separately
        html_size = len(driver.page_source.encode('utf-8'))
        sizes['html']['transfer'] = html_size
        sizes['html']['decoded'] = html_size  # Assume no compression for HTML
        
        # Calculate total sizes
        total_transfer = sum(v['transfer'] for v in sizes.values()) / (1024 * 1024)  # MB
        total_decoded = sum(v['decoded'] for v in sizes.values()) / (1024 * 1024)  # MB
        
        # Calculate compression rates per type (avoid division by zero)
        def calc_compression(transfer, decoded):
            if decoded == 0:
                return 0
            return ((decoded - transfer) / decoded) * 100 if decoded > transfer else 0
        
        compression_rates = {
            'html': calc_compression(sizes['html']['transfer'], sizes['html']['decoded']),
            'css': calc_compression(sizes['css']['transfer'], sizes['css']['decoded']),
            'js': calc_compression(sizes['js']['transfer'], sizes['js']['decoded']),
            'images': calc_compression(sizes['images']['transfer'], sizes['images']['decoded']),
            'other': calc_compression(sizes['other']['transfer'], sizes['other']['decoded'])
        }
        
        # Overall compression rate
        overall_compression = calc_compression(
            sum(v['transfer'] for v in sizes.values()),
            sum(v['decoded'] for v in sizes.values())
        )
        
        driver.quit()
        
        return {
            "Server Response Time": round(server_response, 1),
            "All Content Loaded Time": round(content_loaded, 1),
            "Scripts Complete Time": round(scripts_complete, 1),
            "Total Page Size (MB)": round(total_transfer, 2),
            "HTML Size (MB)": round(sizes['html']['transfer'] / (1024 * 1024), 2),
            "CSS Size (MB)": round(sizes['css']['transfer'] / (1024 * 1024), 2),
            "JS Size (MB)": round(sizes['js']['transfer'] / (1024 * 1024), 2),
            "Image Size (MB)": round(sizes['images']['transfer'] / (1024 * 1024), 2),
            "Other Size (MB)": round(sizes['other']['transfer'] / (1024 * 1024), 2),
            "Compression Rate (%)": round(overall_compression, 0),
            "HTML Compression (%)": round(compression_rates['html'], 0),
            "CSS Compression (%)": round(compression_rates['css'], 0),
            "JS Compression (%)": round(compression_rates['js'], 0),
            "Image Compression (%)": round(compression_rates['images'], 0),
            "Other Compression (%)": round(compression_rates['other'], 0)
        }
        
    except Exception as e:
        print(f"Error getting performance metrics: {e}")
        return None"""


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
        robots_response = requests.get(robots_url, headers=headers, timeout=5)
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

def check_hreflang(html_content):
    """Check for hreflang tags"""
    hreflang_tags = []
    soup = BeautifulSoup(html_content, 'html.parser')
    for link in soup.find_all('link', attrs={'hreflang': True}):
        hreflang_tags.append({
            'lang': link.get('hreflang'),
            'href': link.get('href')
        })
    return hreflang_tags

def check_schema_markup(html_content):
    """Check for schema.org markup"""
    schema_types = []
    soup = BeautifulSoup(html_content, 'html.parser')
    for script in soup.find_all('script', type='application/ld+json'):
        try:
            schema_data = json.loads(script.string)
            if isinstance(schema_data, dict):
                schema_types.append(schema_data.get('@type', 'Unknown'))
            elif isinstance(schema_data, list):
                for item in schema_data:
                    schema_types.append(item.get('@type', 'Unknown'))
        except json.JSONDecodeError:
            continue
    return list(set(schema_types))  # Return unique types

def check_analytics(html_content):
    """Comprehensive analytics detection focusing on head section and common implementation patterns"""
    from bs4 import BeautifulSoup
    import re
    
    analytics_services = set()
    
    # Extended detection patterns with multiple verification points
    analytics_patterns = {
        'Google Analytics': {
            'scripts': [
                r'googletagmanager\.com/gtag/js',
                r'google-analytics\.com/analytics\.js',
                r'google-analytics\.com/ga\.js'
            ],
            'init': [
                r'gtag\(',
                r'ga\([^)]*create',
                r'GoogleAnalyticsObject'
            ]
        },
        'Google Tag Manager': {
            'scripts': [
                r'googletagmanager\.com/gtm\.js',
                r'googletagmanager\.com/gtag/js'
            ],
            'init': [
                r'GTM-\w+',
                r'dataLayer\s*=\s*\[\]'
            ]
        },
        'Facebook Pixel': {
            'scripts': [
                r'connect\.facebook\.net/[^/]+/fbevents\.js'
            ],
            'init': [
                r'fbq\(',
                r'!function\(f,b,e,v,n,t,s\)'
            ]
        },
        'Hotjar': {
            'scripts': [
                r'static\.hotjar\.com/c/hotjar-\d+\.js'
            ],
            'init': [
                r'hj\(',
                r'hotjar\.identify'
            ]
        },
        'Matomo': {
            'scripts': [
                r'matomo\.js',
                r'piwik\.js'
            ],
            'init': [
                r'_paq\s*=\s*\[\]',
                r'_paq\.push'
            ]
        },
        'Microsoft Clarity': {
            'scripts': [
                r'clarity\.ms/tag'
            ],
            'init': [
                r'clarity\.identify'
            ]
        }
    }

    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        head = soup.head if soup.head else soup  # Fallback to entire document if no head
        
        # Check all script tags
        for script in head.find_all('script', recursive=True):
            script_content = ''
            
            # Check external scripts
            if script.has_attr('src'):
                src = script['src']
                for service, patterns in analytics_patterns.items():
                    for pattern in patterns['scripts']:
                        if re.search(pattern, src, re.IGNORECASE):
                            analytics_services.add(service)
            
            # Check inline scripts
            if script.string:
                script_content = script.string
                for service, patterns in analytics_patterns.items():
                    for pattern in patterns['init']:
                        if re.search(pattern, script_content, re.IGNORECASE):
                            analytics_services.add(service)
        
        # Check noscript implementations (common fallback)
        for noscript in soup.find_all('noscript', recursive=True):
            noscript_content = str(noscript)
            for service, patterns in analytics_patterns.items():
                for pattern in patterns['scripts'] + patterns['init']:
                    if re.search(pattern, noscript_content, re.IGNORECASE):
                        analytics_services.add(service)
        
        # Check for GTM iframe
        for iframe in soup.find_all('iframe', recursive=True):
            if iframe.has_attr('src'):
                src = iframe['src']
                if 'googletagmanager.com/ns.html' in src:
                    analytics_services.add('Google Tag Manager')
        
        # Check for data attributes
        for tag in soup.find_all(attrs={'data-analytics': True}):
            value = tag['data-analytics'].lower()
            for service in analytics_patterns.keys():
                if service.lower() in value:
                    analytics_services.add(service)
    
    except Exception as e:
        print(f"Error parsing HTML for analytics: {str(e)}")
    
    return sorted(analytics_services)

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


def append_metrics_to_dict(metrics, url, last_modified, seo_metrics, desktop_metrics, mobile_metrics, sitemap_url, moz_summary):
    metrics["URL"].append(url)
    metrics['Last Modified'].append(last_modified)
    metrics['Meta Title'].append(seo_metrics.get("Meta Title", "N/A"))
    metrics['Meta Title Character Count'].append(seo_metrics.get("Meta Title Character Count", "N/A"))
    metrics['Meta Description'].append(seo_metrics.get("Meta Description", "N/A"))
    metrics['Meta Description Character Count'].append(seo_metrics.get("Meta Description Character Count", "N/A"))
    metrics['Word Count'].append(seo_metrics.get("Word Count", "N/A"))
    metrics['H1 Tags'].append(seo_metrics.get("H1 Tags", "N/A"))
    metrics['H2 Tags'].append(seo_metrics.get("H2 Tags", "N/A"))
    metrics['Canonical Tag'].append(seo_metrics.get("Canonical Tag", "N/A"))
    metrics['Largest Image Name'].append(seo_metrics.get("Largest Image Name", "N/A"))
    metrics['Largest Image Size (KB)'].append(seo_metrics.get("Largest Image Size (KB)", "N/A"))
    metrics['Structured Data'].append(seo_metrics.get("Structured Data", "N/A"))
    metrics['Internal Links'].append(seo_metrics.get("Internal Links", "N/A"))
    metrics['External Links'].append(seo_metrics.get("External Links", "N/A"))
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
    metrics["Broken Links"].append("N/A")
    metrics["Image Details"].append(seo_metrics.get("Image Details", []))
    metrics["Email Privacy Issues"].append(", ".join(seo_metrics.get("Email Privacy Issues", [])) or "None")
    metrics["Flash Used"].append(seo_metrics.get("Flash Used", "No"))
    metrics["iFrames Used"].append(seo_metrics.get("iFrames Used", "No"))
    metrics["Favicon Used"].append(seo_metrics.get("Favicon Used", "No"))
    
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
                return redirect(url_for('analyze_single_url'))
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
                """flash('Email already exists. You already have an account. Please <a href="{}">login</a>.'.format(url_for('login')), 'danger')
                return redirect(url_for('register'))"""

            user = User(name=name, email=email, country=country, password=password, is_verified=False)

            # Generate and assign email verification token
            token = secrets.token_urlsafe(32)
            user.verification_token = token

            db.session.add(user)
            db.session.commit()

            url_usage = UserUrlUsage(user_id=user.id, urls_used=0)
            db.session.add(url_usage)
            db.session.commit()
            
            # Assign free plan after registration
            free_plan = Plan.query.filter_by(name="Free").first()
            if free_plan:
                user_plan = UserPlan(
                    user_id=user.id,
                    plan_id=free_plan.id
                )
                db.session.add(user_plan)
                db.session.commit()

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

"""@app.route('/dashboard/<username>', methods=['GET', 'POST'])
@login_required
def dashboard(username):
    form = AnalysisForm()
   
    if 'user' in session and session['user'] == current_user.email:
        analyzed_sites = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).all()
        
        # Get the latest analysis for the metrics display
        latest_analysis = analyzed_sites[0] if analyzed_sites else None

        # Fetch the user's most recent plan
        user_plan = UserPlan.query.filter_by(user_id=current_user.id).order_by(UserPlan.start_date.desc()).first()
        
        plan_expired = False
        free_trial_over = False

        if user_plan:
            plan = user_plan.plan

            # Corrected analyzed URLs count
            #analyzed_urls_count = sum(len(fetch_urls_from_sitemap(a.url) or []) for a in analyzed_sites)
            url_usage = UserUrlUsage.query.filter_by(user_id=current_user.id).first()
            analyzed_urls_count = url_usage.urls_used if url_usage else 0
            urls_remaining = plan.max_urls - analyzed_urls_count

            # Check if the user has exceeded their URL limit
            if analyzed_urls_count >= plan.max_urls:
                if plan.name == "Free":
                    free_trial_over = True
                else:
                    plan_expired = True

            # Duration check
            if plan.duration:
                start_date = user_plan.start_date
                end_date = start_date + timedelta(days=plan.duration * 30)
                if datetime.utcnow() > end_date:
                    plan_expired = True

        # Calculate remaining URLs
        urls_remaining = plan.max_urls - analyzed_urls_count if user_plan else 0

        # Calculate remaining days (if the plan has a duration)
        remaining_days = None
        if user_plan and plan.duration:
            end_date = user_plan.start_date + timedelta(days=plan.duration * 30)
            remaining_days = (end_date - datetime.utcnow()).days
            remaining_days = max(0, remaining_days)  # Ensure it doesn't go negative

        return render_template(
            'dashboard.html',
            form=form,
            plan=plan if user_plan else None,
            analyzed_sites=analyzed_sites,
            latest_analysis=latest_analysis,
            analyzed_urls_count=analyzed_urls_count,
            urls_remaining=urls_remaining,
            remaining_days=remaining_days,
            plan_expired=plan_expired,
            free_trial_over=free_trial_over,
            username=username,
            country=current_user.country.lower()
        )
    
    # Redirect to login if user is not authenticated
    flash("Unauthorized access!", "danger")
    return redirect(url_for("login"))"""

@app.route('/dashboard/<username>', methods=["GET", "POST"])
@login_required
def dashboard(username):
    form = AnalysisForm()
   
    if 'user' in session and session['user'] == current_user.email:
        analyzed_sites = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).all()
        
        # Get the latest analysis for the metrics display
        latest_analysis = analyzed_sites[0] if analyzed_sites else None

        # Fetch the user's most recent plan
        user_plan = UserPlan.query.filter_by(user_id=current_user.id).order_by(UserPlan.start_date.desc()).first()
        
        plan_expired = False
        free_trial_over = False
        remaining_days = 0
        urls_remaining = 0

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

        return render_template(
            'dashboard.html',
            form=form,
            plan=user_plan.plan if user_plan else None,
            analyzed_sites=analyzed_sites,
            latest_analysis=latest_analysis,
            analyzed_urls_count=analyzed_urls_count,
            urls_remaining=urls_remaining,
            remaining_days=remaining_days,
            plan_expired=plan_expired,
            free_trial_over=free_trial_over,
            username=username,
            country=current_user.country.lower()
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

@app.route("/check_analysis_status", methods=["GET"])
@login_required
def check_analysis_status():
    user_id = current_user.id
    return jsonify({"is_running": user_id in running_analyses})




@app.route("/download_report")
@login_required 
def download_report():
    try:

        if not session.get('metrics'):
            flash("No analysis data found. Please perform an analysis first.", "warning")
            return redirect(url_for("analyze_single_url"))
        # Get all required data from session
        data = {
            'metrics': session.get('metrics'),
            'grade': session.get('grade'),
            'weighted_score': session.get('weighted_score'),
            'category_grades': session.get('category_grades'),
            'recommendations': session.get('recommendations'),
            'now': datetime.now()
        }
        
        # Check for missing data
        missing = [k for k, v in data.items() if v is None and k != 'now']
        if missing:
            flash(f"Missing data for report: {', '.join(missing)}", "warning")
            return redirect(url_for("analyze_single_url"))
        
        # Generate PDF
        html = render_template("simple_report.html", **data)
        config = pdfkit.configuration(wkhtmltopdf='/usr/bin/wkhtmltopdf')
        pdf = pdfkit.from_string(html, False, configuration=config)
        
        return send_file(
            BytesIO(pdf),
            download_name="seo_report.pdf",
            as_attachment=True
        )
        
    except Exception as e:
        flash(f"PDF generation failed: {str(e)}", "danger")
        return redirect(url_for("analyze_single_url"))

@app.route("/", methods=["GET", "POST"])
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

            #screenshots = capture_device_screenshots(url)
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Perform additional checks
            robots_info = check_robots_txt(base_url)
            sitemap_info = guess_sitemap_url(base_url)
            hreflang_tags = check_hreflang(seo_metrics.get('html_content', ''))
            schema_types = check_schema_markup(seo_metrics.get('html_content', ''))
            analytics_services = check_analytics(seo_metrics.get('html_content', ''))
            ssl_info = check_ssl_certificate(parsed_url.netloc)
            images_without_alt = count_images_without_alt(seo_metrics.get('Image Details', []))
            
            api_key = app.config["GOOGLE_API_KEY"]
            desktop_metrics = fetch_pagespeed_metrics(url, "desktop", api_key)
            mobile_metrics = fetch_pagespeed_metrics(url, "mobile", api_key)
            
            # Get performance metrics
            performance_metrics = get_performance_metrics(url)
            screenshots = capture_device_screenshots(url)
            
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
                "Email Privacy Issues": [", ".join(seo_metrics.get("Email Privacy Issues", [])) or "None"],
                "Flash Used": [seo_metrics.get("Flash Used", "No")],
                "iFrames Used": [seo_metrics.get("iFrames Used", "No")],
                "Favicon Used": [seo_metrics.get("Favicon Used", "No")],
                "Domain Authority": [moz_metrics.get("Domain Authority", "N/A")],
                "Page Authority": [moz_metrics.get("Page Authority", "N/A")],
                "Spam Score": [moz_metrics.get("Spam Score", "N/A")],
                "Link Propensity": [moz_metrics.get("Link Propensity", "N/A")],
                "Total Backlinks": [moz_metrics.get("Total Backlinks", "N/A")],
                "Backlink Domain": [moz_metrics.get("Backlink Domain", "N/A")],
                # Performance metrics
                "Server Response Time": [performance_metrics.get("Server Response Time", "N/A") if performance_metrics else "N/A"],
                "All Content Loaded Time": [performance_metrics.get("All Content Loaded Time", "N/A") if performance_metrics else "N/A"],
                "Scripts Complete Time": [performance_metrics.get("Scripts Complete Time", "N/A") if performance_metrics else "N/A"],
                "Total Page Size (MB)": [performance_metrics.get("Total Page Size (MB)", "N/A") if performance_metrics else "N/A"],
                "HTML Size (MB)": [performance_metrics.get("HTML Size (MB)", "N/A") if performance_metrics else "N/A"],
                "CSS Size (MB)": [performance_metrics.get("CSS Size (MB)", "N/A") if performance_metrics else "N/A"],
                "JS Size (MB)": [performance_metrics.get("JS Size (MB)", "N/A") if performance_metrics else "N/A"],
                "Image Size (MB)": [performance_metrics.get("Image Size (MB)", "N/A") if performance_metrics else "N/A"],
                "Other Size (MB)": [performance_metrics.get("Other Size (MB)", "N/A") if performance_metrics else "N/A"],
                "Robots.txt": [robots_info['robots_url'] if robots_info['exists'] else "Not found"],
                "Sitemap.xml": [sitemap_info['sitemap_url'] if sitemap_info['exists'] else "Not found"],
                "Disallowed Paths": [", ".join(robots_info['disallowed_paths']) if robots_info['disallowed_paths'] else "None"],
                "Hreflang Tags": [len(hreflang_tags) if hreflang_tags else "None"],
                "Schema Types": [", ".join(schema_types) if schema_types else "None"],
                "Analytics Services": [", ".join(analytics_services) if analytics_services else "None"],
                "SSL Enabled": ["Yes" if ssl_info['has_ssl'] else "No"],
                "SSL Expiry Date": [ssl_info['expiry_date']],
                "Images Without Alt": [images_without_alt],
            }

            # Store metrics in session if needed for redirects
            session['metrics'] = metrics
            session['grade'] = grade_results['overall']
            session['weighted_score'] = grade_results['weighted_score']
            session['category_grades'] = grade_results['categories']
            session['recommendations'] = recommendations
            session['hreflang_tags'] = hreflang_tags
            session['schema_types'] = schema_types
            session['analytics_services'] = analytics_services
            session['ssl_info'] = ssl_info
            session['images_without_alt'] = images_without_alt
            session.modified = True
            
            # Render the template with both form and metrics
            return render_template("index.html", 
                                form=form, 
                                latest_update=latest_update, 
                                metrics=metrics, 
                                grade=grade_results['overall'], 
                                category_grades=grade_results['categories'], 
                                weighted_score=grade_results['weighted_score'],
                                recommendations=recommendations,
                                from_post=True,
                                performance_metrics=performance_metrics,
                                screenshots=screenshots,
                                hreflang_tags=hreflang_tags,
                                schema_types=schema_types,
                                analytics_services=analytics_services,
                                ssl_info=ssl_info,
                                images_without_alt=images_without_alt)

        except Exception as e:
            flash(f"An error occurred during analysis: {str(e)}", "danger")
            return redirect(url_for("analyze_single_url"))
    
    # Handle GET requests or when form validation fails
    metrics = session.pop('metrics', None)
    recommendations = []
    return render_template("index.html", 
                         form=form, 
                         metrics=metrics, 
                         grade=None, 
                         category_grades=None, 
                         weighted_score=None, 
                         recommendations=recommendations, 
                         from_post=False,
                         performance_metrics=None,
                           hreflang_tags=[],
                     schema_types=[],
                     analytics_services=[],
                     ssl_info={
                         'has_ssl': False,
                         'expiry_date': 'N/A',
                         'days_remaining': 'N/A'
                     },
                     images_without_alt=0,
                     screenshots={})


    
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

@app.route('/get_analysis_results')
@login_required
def get_analysis_results():
    analysis_id = request.args.get('id')
    analysis = Analysis.query.get(analysis_id)
    
    if not analysis or analysis.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Analysis not found'})
    
    # Calculate remaining URLs
    user_plan = UserPlan.query.filter_by(user_id=current_user.id).order_by(UserPlan.start_date.desc()).first()
    remaining_urls = 0
    if user_plan:
        analyzed_urls = []
        for a in Analysis.query.filter_by(user_id=current_user.id).all():
            urls = fetch_urls_from_sitemap(a.url) or []
            analyzed_urls.extend(urls)
        analyzed_urls_count = len(analyzed_urls)
        remaining_urls = max(0, user_plan.plan.max_urls - analyzed_urls_count)
    
    return jsonify({
        'success': True,
        'result': {
            'id': analysis.id,
            'website_name': analysis.website_name,
            'url': analysis.url,
            'excel_file': analysis.excel_file is not None
        },
        'remaining_urls': remaining_urls
    })


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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

@app.route("/analyze", methods=["GET", "POST"])
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
    app.run(debug=True, port=5022)


