from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session
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
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Length, Email, EqualTo
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
api_key = os.getenv("GOOGLE_API_KEY")  # Replace with your Google API key

# Moz API credentials
moz_access_id = os.getenv("MOZ_ACCESS_ID")
moz_secret_key = os.getenv("MOZ_SECRET_KEY")



# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'  # Change if using another SMTP service
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  # Replace with your email
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # Replace with app-specific password if using Gmail
app.config['MAIL_DEFAULT_SENDER'] = 'support@magnustic.com'

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
    "Image Details": []  # Initialize image details list
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
    db.drop_all()  # Drop all tables
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

def fetch_moz_metrics(url):
    """Fetch Moz metrics for a given URL."""
    auth_string = f"{moz_access_id}:{moz_secret_key}"
    auth_header = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
    api_url = "https://lsapi.seomoz.com/v2/url_metrics"
    data = {
        "targets": [url],
        "metrics": ["domain_authority", "subdomain", "page_authority", "spam_score", "link_propensity", "Backlink Domain"]
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
            "Backlink Domain": "Error"
        }
    
def analyze_page(url):
    """Analyze a single web page for SEO parameters, including broken links and image details."""
    html_content = fetch_html(url)
    if not html_content:
        return None

    soup = BeautifulSoup(html_content, "lxml")

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
        "Image Details": image_details  # Add image details to the return dictionary
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

def guess_sitemap_url(base_url):
    """Guess common sitemap locations and handle direct inputs."""
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
    return None

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
    metrics["Image Details"].append(seo_metrics.get("Image Details", []))  # Add image details

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


def save_metrics_to_excel(metrics, sitemap_url, moz_summary):
    try:
        # Create a directory for analysis reports if it doesn't exist
        reports_dir = os.path.join(os.getcwd(), "analysis_reports")
        os.makedirs(reports_dir, exist_ok=True)

        domain = urlparse(sitemap_url).netloc
        domain_name = domain.replace("www.", "").replace(".", "_")
        date_str = datetime.now().strftime("%Y%m%d")
        filename = f"seo_moz_analysis_{domain_name}_{date_str}.xlsx"
        file_path = os.path.join(reports_dir, filename)

        # Convert new data to DataFrames
        moz_df = pd.DataFrame(moz_summary)
        seo_df = pd.DataFrame.from_dict(metrics)

        # Extract image details
        image_details = []
        for url, details in zip(metrics["URL"], metrics["Image Details"]):
            for image in details:
                image_details.append({
                    "URL": url,
                    "Image URL": image["Image URL"],
                    "Alt Tag": image["Alt Tag"],
                    "Image Size (KB)": image["Image Size (KB)"]
                })

        image_df = pd.DataFrame(image_details)

        # Write the final data back to the Excel file with formatting
        with pd.ExcelWriter(file_path, engine="xlsxwriter") as writer:
            workbook = writer.book

            # Define yellow header format
            yellow_header_format = workbook.add_format({"bold": True, "bg_color": "yellow", "border": 1})

            # Write Moz Data
            moz_df.to_excel(writer, sheet_name="SEO Analysis", startrow=0, index=False)
            worksheet_moz = writer.sheets["SEO Analysis"]
            for col_num, value in enumerate(moz_df.columns.values):
                worksheet_moz.write(0, col_num, value, yellow_header_format)  # Apply yellow format

            # Write SEO Data
            seo_df.to_excel(writer, sheet_name="SEO Analysis", startrow=len(moz_df) + 3, index=False)
            worksheet_seo = writer.sheets["SEO Analysis"]
            for col_num, value in enumerate(seo_df.columns.values):
                worksheet_seo.write(len(moz_df) + 3, col_num, value, yellow_header_format)  # Apply yellow format

            # Write Image Optimization Data
            image_df.to_excel(writer, sheet_name="Image Optimization", index=False)

        print(f"Data saved to {file_path}")
        return file_path  # Return the file path

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

def send_to_wordpress(data):
    # WordPress REST API endpoint
    wordpress_url = "http://http://localhost/transcription/wp-json/seo/v1/analysis"

    # Send the data as JSON
    try:
        response = requests.post(wordpress_url, json=data, headers={"Content-Type": "application/json"})
        response.raise_for_status()
        print("Data sent to WordPress successfully!")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error sending data to WordPress: {e}")
        return None


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
                session['user'] = user.email  # Changed from username to email
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard', username=user.email))  # Using email as username
            else:
                flash('Incorrect password.', 'danger')
        else:
            flash('Login failed. User not found.', 'danger')
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
                flash('Email already exists. Please use a different one.', 'danger')
                return redirect(url_for('register'))

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
            return redirect(url_for('login'))  # Changed from dashboard to login

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

@app.route('/dashboard/<username>', methods=['GET', 'POST'])
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

@app.route("/cancel_analysis", methods=["POST"])
@login_required
@csrf.exempt
def cancel_analysis():
    user_id = current_user.id
    if user_id in running_analyses:
        thread, cancel_event = running_analyses[user_id]
        cancel_event.set()  # Stop the running thread
        del running_analyses[user_id]  # Remove the entry from the dictionary
        return jsonify({"success": True, "message": "Analysis has been canceled."})
    else:
        return jsonify({"error": "No active analysis to cancel."}), 400


@app.route("/", methods=["GET", "POST"])
def analyze_single_url():
    form = AnalysisForm()
    
    if form.validate_on_submit():  # This checks CSRF automatically
        try:
            url = form.url.data.strip()
            
            if not url:
                flash("Please provide a valid URL.", "danger")
                return redirect(url_for("index"))

            # Analyze the single URL
            seo_metrics = analyze_page(url)
            if not seo_metrics:
                flash("Failed to analyze the URL.", "danger")
                return redirect(url_for("index"))

            desktop_metrics = fetch_pagespeed_metrics(url, "desktop", api_key)
            mobile_metrics = fetch_pagespeed_metrics(url, "mobile", api_key)

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
                "Image Details": [seo_metrics.get("Image Details", [])]
            }

            # Store metrics in session if needed for redirects
            session['metrics'] = metrics
            
            # Render the template with both form and metrics
            return render_template("index.html", form=form, metrics=metrics, from_post=True)

        except Exception as e:
            flash(f"An error occurred during analysis: {str(e)}", "danger")
            return redirect(url_for("index"))
    
    # Handle GET requests or when form validation fails
    metrics = session.pop('metrics', None)
    return render_template("index.html", form=form, metrics=metrics, from_post=False)

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



@app.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    form = AnalysisForm()
    print("CSRF Token:", form.csrf_token._value())
    if form.validate_on_submit():
        print("Form validated successfully")
        try:
            # Ensure user session is valid
            if "user" not in session or session["user"] != current_user.email:
                flash("Unauthorized access!", "danger")
                return redirect(url_for("login"))

            # Fetch user plan
            user_plan = UserPlan.query.filter_by(user_id=current_user.id).order_by(UserPlan.start_date.desc()).first()
            if not user_plan:
                flash("You do not have an active plan. Please select a plan before analyzing.", "warning")
                return redirect(url_for("select_plan"))

            plan = user_plan.plan
            max_urls = plan.max_urls

            # Count analyzed URLs
            #analyzed_urls_count = sum(len(fetch_urls_from_sitemap(a.url) or []) for a in Analysis.query.filter_by(user_id=current_user.id).all())
            url_usage = UserUrlUsage.query.filter_by(user_id=current_user.id).first()
            analyzed_urls_count = url_usage.urls_used if url_usage else 0


            # Count analyzed URLs only for this user
            analyzed_urls_count = 0
            user_analyses = Analysis.query.filter_by(user_id=current_user.id).all()
            for analysis in user_analyses:
                urls = fetch_urls_from_sitemap(analysis.url) or []
                analyzed_urls_count += len(urls)


            # Check if user has exceeded URL limit
            if analyzed_urls_count >= max_urls:
                flash(f"You have reached the limit of {max_urls} URLs. Upgrade your plan to analyze more.", "danger")
                return redirect(url_for("dashboard", username=current_user.email))

            # Get the URL from the form
            url = form.url.data.strip()
            if not is_valid_url(url):
                flash("Invalid URL provided.", "danger")
                return redirect(url_for("dashboard", username=current_user.email))

            parsed_url = urlparse(url)
            
            # Determine sitemap URL
            if url.endswith(".xml"):
                sitemap_url = url
            else:
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                sitemap_url = guess_sitemap_url(base_url)

            # If sitemap is not found, try an alternative method
            if not sitemap_url:
                print("No sitemap found using the first method. Trying alternative method.")
                base_url = form.url.data.strip()  # Use the same URL as a fallback
                sitemap_url = guess_sitemap_url(base_url)
                if not sitemap_url:
                    flash("No sitemap could be found. Please check the URL and try again.", "danger")
                    return redirect(url_for("dashboard", username=current_user.email))

            # Create a cancel event for this analysis
            cancel_event = Event()
            running_analyses[current_user.id] = (threading.current_thread(), cancel_event)

            # Fetch Moz metrics for the domain
            domain = parsed_url.netloc
            print(f"Fetching Moz metrics for domain: {domain}")
            moz_metrics = fetch_moz_metrics(domain)
            moz_metrics["Spam Score"] = f"{moz_metrics.get('Spam Score', 'N/A')}%"

            moz_summary = {
                "Metric": ["Domain Authority", "Subdomain", "Page Authority", "Spam Score", "Link Propensity", "Backlink Domain"],
                "Value": [
                    moz_metrics.get("Domain Authority", "N/A"),
                    moz_metrics.get("Subdomain", "N/A"),
                    moz_metrics.get("Page Authority", "N/A"),
                    moz_metrics.get("Spam Score", "N/A"),
                    moz_metrics.get("Link Propensity", "N/A"),
                    moz_metrics.get("Backlink Domain", "N/A"),
                ],
            }

            # Initialize metrics dictionary
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
                "Image Details": []
            }

            # Fetch URLs from the sitemap
            sitemap_entries = fetch_sitemap_urls(sitemap_url) or []
            urls_analyzed = 0

            if sitemap_entries:
                for sitemap_url, last_modified in sitemap_entries:
                    urls = fetch_urls_from_sitemap(sitemap_url) or []

                    for url in urls:
                        # Check if the analysis has been canceled
                        if cancel_event.is_set():
                            flash("Analysis canceled by the user.", "warning")
                            return redirect(url_for("dashboard", username=current_user.email))

                        if analyzed_urls_count + urls_analyzed >= max_urls:
                            flash(f"You have reached the limit of {max_urls} URLs. Upgrade your plan for more.", "warning")
                            break

                        print(f"Analyzing SEO metrics for URL {urls_analyzed + 1}: {url}")

                        seo_metrics = analyze_page(url)
                        if not seo_metrics:
                            continue

                        desktop_metrics = fetch_pagespeed_metrics(url, "desktop", api_key)
                        mobile_metrics = fetch_pagespeed_metrics(url, "mobile", api_key)

                        append_metrics_to_dict(metrics, url, last_modified, seo_metrics, desktop_metrics, mobile_metrics, sitemap_url, moz_summary)
                        urls_analyzed += 1
                        

            else:
                # Fallback to direct sitemap parsing
                urls = fetch_and_parse_sitemap(sitemap_url) or []

                for url in urls:
                    # Check if the analysis has been canceled
                    if cancel_event.is_set():
                        flash("Analysis canceled by the user.", "warning")
                        return redirect(url_for('dashboard', username=current_user.email))

                    if urls_analyzed >= max_urls:
                        flash("You have reached the limit. Upgrade your plan for full analysis.", "warning")
                        save_metrics_to_excel(metrics, sitemap_url, moz_summary)
                        return render_template("result.html", sitemap_urls=sitemap_url, metrics=metrics, excel_file="seo_moz_analysis.xlsx")

                    print(f"Analyzing SEO metrics for URL {urls_analyzed + 1}: {url}")
                    seo_metrics = analyze_page(url)

                    if not seo_metrics:
                        print(f"Skipping URL due to SEO fetch failure: {url}")
                        continue

                    desktop_metrics = fetch_pagespeed_metrics(url, "desktop", api_key)
                    mobile_metrics = fetch_pagespeed_metrics(url, "mobile", api_key)

                    append_metrics_to_dict(metrics, url, "N/A", seo_metrics, desktop_metrics, mobile_metrics, sitemap_url, moz_summary)
                    urls_analyzed += 1
                   

            # Update remaining URLs
            if url_usage and urls_analyzed > 0:
                url_usage.urls_used += urls_analyzed
                db.session.commit()
            
            # Save analysis results to an Excel file
            excel_file = save_metrics_to_excel(metrics, sitemap_url, moz_summary)
            if not excel_file:
                flash("Error saving analysis to Excel.", "danger")
                return redirect(url_for('dashboard', username=current_user.email))
            user_plan = UserPlan.query.filter_by(user_id=current_user.id).order_by(UserPlan.start_date.desc()).first()
                
            grade = calculate_grade(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics)
            
            # Save analysis in the database
            analysis = Analysis(
                website_name=domain,
                url=sitemap_url,
                excel_file=excel_file,
                user_id=current_user.id,
                grade=grade,
                moz_metrics=moz_metrics,
                metrics=metrics
            )
            db.session.add(analysis)
            db.session.commit()
            
            flash("Analysis completed successfully!", "success")
            return jsonify({
                "success": True,
                "analysis_id": analysis.id
            })
            
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred during analysis: {str(e)}", "danger")
            return jsonify({
                "success": False,
                "message": str(e)
            }), 400
                

    # If it's a GET request, render the dashboard template
    print("Form validation failed")
    return render_template("dashboard.html", form=form, username=current_user.username)


if __name__ == "__main__":
    app.run(debug=True, port=1365)
