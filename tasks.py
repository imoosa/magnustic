from urllib.parse import urlparse
from datetime import datetime
import os
import sys
import redis
import json
import re
import time
import threading

# Add the current directory to Python path to import from main
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# DRAMATIQ IMPORTS - Only import once at the top
import dramatiq
from dramatiq.brokers.redis import RedisBroker
from dramatiq.results import Results
from dramatiq.results.backends import RedisBackend
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import necessary functions from main.py
from main import app, db
from main import SingleUrlJob, AnalysisJob, Analysis, UserUrlUsage
from main import (
    fetch_moz_metrics,
    guess_sitemap_url,
    fetch_sitemap_urls,
    fetch_urls_from_sitemap,
    fetch_and_parse_sitemap,
    extract_all_urls_from_sitemap,
    append_metrics_to_dict,
    calculate_grade,
    get_unique_filename,
    save_metrics_to_excel,
    fetch_html, 
    analyze_page, 
    generate_recommendations,
    singlepage_grade, 
    get_performance_metrics,
    capture_device_screenshots, 
    check_robots_txt,
    check_hreflang,
    check_schema_markup, 
    detect_analytics,
    check_ssl_certificate, 
    count_images_without_alt,
    fetch_latest_google_update, 
    is_valid_url,
    fetch_open_pagerank_metrics,
    fetch_pagespeed_metrics_lighthouse,
    fetch_sitemap_data,
    check_url_in_sitemap,
)

try:
    from main import keyword_analyzer
except ImportError:
    # Create a new instance if import fails
    from main import SimpleKeywordAnalyzer
    keyword_analyzer = SimpleKeywordAnalyzer()

# Get Redis URL from environment
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Setup Redis broker with Results middleware - Do this only once
result_backend = RedisBackend(url=redis_url)
broker = RedisBroker(url=redis_url)
broker.add_middleware(Results(backend=result_backend))
dramatiq.set_broker(broker)

# Redis connection for storing job data
redis_conn = redis.Redis.from_url(redis_url, decode_responses=True)

# Custom exception for task cancellation
class TaskAborted(Exception):
    """Custom exception for aborted tasks"""
    pass

def fetch_pagespeed_parallel(url):
    """
    Fetches Desktop and Mobile PageSpeed metrics simultaneously using threads.
    This replaces the old sequential fetch_pagespeed_metrics_lighthouse call
    and cuts PageSpeed wait time roughly in half.
    """
    desktop_result = {}
    mobile_result = {}

    def fetch_desktop():
        try:
            d, _ = fetch_pagespeed_metrics_lighthouse(url)
            return d
        except Exception as e:
            print(f"[PageSpeed Desktop Error] {url}: {e}")
            return {
                "Performance Score": "Error",
                "First Contentful Paint": "Error",
                "Speed Index": "Error",
                "Time to Interactive": "Error",
                "First Meaningful Paint": "Error",
                "CLS Lighthouse": "Error",
                "LCP Lighthouse": "Error",
            }

    def fetch_mobile():
        try:
            _, m = fetch_pagespeed_metrics_lighthouse(url)
            return m
        except Exception as e:
            print(f"[PageSpeed Mobile Error] {url}: {e}")
            return {
                "Performance Score": "Error",
                "First Contentful Paint": "Error",
                "Speed Index": "Error",
                "Time to Interactive": "Error",
                "First Meaningful Paint": "Error",
                "CLS Lighthouse": "Error",
                "LCP Lighthouse": "Error",
            }

    with ThreadPoolExecutor(max_workers=2) as ex:
        f_desktop = ex.submit(fetch_desktop)
        f_mobile = ex.submit(fetch_mobile)
        desktop_result = f_desktop.result(timeout=60)
        mobile_result = f_mobile.result(timeout=60)

    return desktop_result, mobile_result


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Cached PageSpeed fetch using Redis (avoids repeat API calls)
# ─────────────────────────────────────────────────────────────────────────────
def fetch_pagespeed_cached(url):
    """
    Checks Redis for a cached PageSpeed result before hitting the API.
    Cache TTL is 24 hours. On cache miss, calls fetch_pagespeed_parallel.
    """
    cache_key = f"pagespeed_cache:{url}"
    try:
        cached = redis_conn.get(cache_key)
        if cached:
            print(f"[PageSpeed Cache HIT] {url}")
            data = json.loads(cached)
            return data["desktop"], data["mobile"]
    except Exception:
        pass  # Cache miss or Redis error — fall through to live fetch

    desktop, mobile = fetch_pagespeed_parallel(url)

    try:
        redis_conn.setex(cache_key, 86400, json.dumps({"desktop": desktop, "mobile": mobile}))
    except Exception:
        pass  # Non-critical — continue even if caching fails

    return desktop, mobile


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Analyze a single URL (SEO + PageSpeed) — used in bulk parallel loops
# ─────────────────────────────────────────────────────────────────────────────
def _analyze_url_worker(url_to_analyze):
    """
    Worker function that runs analyze_page + PageSpeed (parallel desktop/mobile)
    for a single URL. Designed to be submitted to a ThreadPoolExecutor.

    Returns: (url, seo_metrics, desktop_metrics, mobile_metrics)
    """
    seo_metrics = None
    desktop_metrics = None
    mobile_metrics = None

    try:
        seo_metrics = analyze_page(url_to_analyze)
    except Exception as e:
        print(f"[analyze_page Error] {url_to_analyze}: {e}")

    try:
        desktop_metrics, mobile_metrics = fetch_pagespeed_cached(url_to_analyze)
    except Exception as e:
        print(f"[PageSpeed Error] {url_to_analyze}: {e}")
        err = {
            "Performance Score": "Error",
            "First Contentful Paint": "Error",
            "Speed Index": "Error",
            "Time to Interactive": "Error",
            "First Meaningful Paint": "Error",
            "CLS Lighthouse": "Error",
            "LCP Lighthouse": "Error",
        }
        desktop_metrics = err.copy()
        mobile_metrics = err.copy()

    return url_to_analyze, seo_metrics, desktop_metrics, mobile_metrics

@dramatiq.actor(time_limit=9600000)
def analyze_sitemap_task(user_id, url, max_urls, analyzed_urls_count, job_id):
    """Analyze complete website using sitemap"""
    with app.app_context():
        r = redis.Redis.from_url(app.config['REDIS_URL'])
        
        job = AnalysisJob.query.get(job_id)
        if not job:
            return {"error": "Invalid job ID"}

        def check_cancellation():
            """Check if cancellation was requested"""
            if r.get(f"cancel_job:{job_id}"):
                job.status = "canceled"
                job.message = "Cancelled by user"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                r.delete(f"cancel_job:{job_id}")
                raise TaskAborted("Task cancelled by user")

        try:
            # Initial setup
            job.status = "processing"
            job.started_at = datetime.utcnow()
            db.session.commit()

            # First cancellation check
            check_cancellation()

            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            # Get configuration values
            moz_access_id = app.config.get("MOZ_ACCESS_ID", "")
            moz_secret_key = app.config.get("MOZ_SECRET_KEY", "")

            # Sitemap discovery with cancellation check
            check_cancellation()
            print("Attempting to find the sitemap...")
            
            if url.endswith(".xml"):
                sitemap_url = url
            else:
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                sitemap_result = guess_sitemap_url(base_url)
                
                # Check if result is a dict and extract URL
                if isinstance(sitemap_result, dict):
                    sitemap_url = sitemap_result.get('sitemap_url')
                else:
                    sitemap_url = sitemap_result
                
                if not sitemap_url:
                    print("No sitemap found")
                    job.status = "failed"
                    job.message = "No sitemap found"
                    job.completed_at = datetime.utcnow()
                    db.session.commit()
                    return {"error": "No sitemap found"}

            print(f"Found sitemap: {sitemap_url}")

            # Update progress and check cancellation
            job.progress = 10
            job.message = "Fetching Moz metrics"
            db.session.commit()
            check_cancellation()

            # Fetch Moz metrics with cancellation check and error handling
            moz_metrics = {}
            try:
                moz_metrics = fetch_moz_metrics(domain, moz_access_id, moz_secret_key)
                if moz_metrics:
                    moz_metrics["Spam Score"] = f"{moz_metrics.get('Spam Score', 'N/A')}%"
                else:
                    moz_metrics = {
                        "Domain Authority": "N/A",
                        "Page Authority": "N/A", 
                        "Spam Score": "N/A",
                        "Backlink Domain": "N/A"
                    }
                print("Fetched Moz metrics")
            except Exception as e:
                print(f"Error fetching Moz metrics: {str(e)}")
                moz_metrics = {
                    "Domain Authority": "Error",
                    "Page Authority": "Error", 
                    "Spam Score": "Error",
                    "Backlink Domain": "Error"
                }

            # Fetch URLs from sitemap using the new function
            check_cancellation()
            job.progress = 20
            job.message = "Extracting URLs from sitemap"
            db.session.commit()
            
            all_urls = []
            try:
                # Use the new recursive sitemap parser
                all_urls = extract_all_urls_from_sitemap(sitemap_url)
                
                if not all_urls:
                    # Fallback to other methods
                    print("Trying alternative sitemap parsing methods...")
                    all_urls = fetch_and_parse_sitemap(sitemap_url) or []
                    
                    if not all_urls:
                        sitemap_entries = fetch_sitemap_urls(sitemap_url) or []
                        if sitemap_entries:
                            for sitemap_entry, _ in sitemap_entries:
                                check_cancellation()
                                child_urls = fetch_urls_from_sitemap(sitemap_entry) or []
                                all_urls.extend(child_urls)
            except Exception as e:
                print(f"Error fetching sitemap URLs: {str(e)}")
                all_urls = []

            if not all_urls:
                job.status = "failed"
                job.message = "No URLs found in sitemap"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return {"error": "No URLs found in sitemap"}

            # Limit URLs based on user's plan
            all_urls = all_urls[:max_urls - analyzed_urls_count]
            total_urls = len(all_urls)
            print(f"Total URLs to analyze: {total_urls}")

            # Initialize metrics dictionary
            metrics = {
                "URL": [], "Last Modified": [], "Meta Title": [], "Meta Title Character Count": [],
                "Meta Description": [], "Meta Description Character Count": [], "Word Count": [],
                "H1 Tags": [], "H2 Tags": [], "Canonical Tag": [], "Largest Image Name": [],
                "Largest Image Size (KB)": [], "Structured Data": [], "Internal Links": [],
                "External Links": [], "Performance Score (Desktop)": [], "First Contentful Paint (Desktop)": [],
                "Speed Index (Desktop)": [], "Time to Interactive (Desktop)": [], "First Meaningful Paint (Desktop)": [],
                "CLS Lighthouse (Desktop)": [], "LCP Lighthouse (Desktop)": [], "Performance Score (Mobile)": [],
                "First Contentful Paint (Mobile)": [], "Speed Index (Mobile)": [], "Time to Interactive (Mobile)": [],
                "First Meaningful Paint (Mobile)": [], "CLS Lighthouse (Mobile)": [], "LCP Lighthouse (Mobile)": [],
                "Broken Links": [], "Image Details": [], "Indexability": [], "Response Code": [],
                "Email Privacy Issues": [], "Flash Used": [], "iFrames Used": [], "Favicon Used": []
            }

            # URL analysis loop with periodic cancellation checks
            urls_analyzed = 0
            desktop_metrics = None
            mobile_metrics = None
            seo_metrics = None
            
            for index, url_to_analyze in enumerate(all_urls):
                check_cancellation()  # Check at start of each iteration

                print(f"Analyzing URL {index + 1}/{total_urls}: {url_to_analyze}")

                # Update progress
                progress = 30 + ((index + 1) / total_urls) * 60
                job.progress = int(progress)
                job.message = f"Analyzing URL {index + 1}/{total_urls}: {url_to_analyze}"
                db.session.commit()

                # Analyze page with cancellation check
                check_cancellation()
                try:
                    seo_metrics = analyze_page(url_to_analyze)
                    if not seo_metrics:
                        print(f"Skipping {url_to_analyze} - no metrics returned")
                        continue
                except Exception as e:
                    print(f"Error analyzing page {url_to_analyze}: {str(e)}")
                    continue

                # Fetch metrics with cancellation checks
                check_cancellation()
                try:
                    desktop_metrics, mobile_metrics = fetch_pagespeed_metrics_lighthouse(url_to_analyze)
                except Exception as e:
                    print(f"Error fetching performance metrics: {str(e)}")
                    # Create default metrics
                    desktop_metrics = {
                        "Performance Score": "Error",
                        "First Contentful Paint": "Error",
                        "Speed Index": "Error",
                        "Time to Interactive": "Error",
                        "CLS Lighthouse": "Error",
                        "LCP Lighthouse": "Error"
                    }
                    mobile_metrics = desktop_metrics.copy()

                # Append metrics to dictionary
                append_metrics_to_dict(metrics, url_to_analyze, "N/A", seo_metrics, desktop_metrics, mobile_metrics, sitemap_url, moz_metrics)
                urls_analyzed += 1

            # Final report generation with cancellation checks
            check_cancellation()
            job.progress = 95
            job.message = "Generating report"
            db.session.commit()
            
            check_cancellation()
            reports_dir = os.path.join(app.root_path, "analysis_reports")
            os.makedirs(reports_dir, exist_ok=True)

            domain_name = domain.replace("www.", "").replace(".", "_")
            filename = f"seo_moz_analysis_{domain_name}_{datetime.now().strftime('%Y%m%d')}.xlsx"
            excel_path = os.path.join(reports_dir, get_unique_filename(filename))

            # Save metrics to Excel
            saved_path = save_metrics_to_excel(metrics, sitemap_url, moz_metrics, excel_path)
            if not saved_path:
                job.status = "failed"
                job.message = "Failed to generate report"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return {"error": "Failed to create Excel file"}

            # Calculate grade and save analysis
            check_cancellation()
            if seo_metrics and desktop_metrics and mobile_metrics:
                grade = calculate_grade(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics)
            else:
                grade = "B"  # Default grade for bulk analysis

            analysis = Analysis(
                website_name=domain,
                url=sitemap_url,
                excel_file=saved_path,
                user_id=user_id,
                grade=grade,
                moz_metrics=moz_metrics,
                metrics=metrics
            )
            db.session.add(analysis)
            db.session.flush()

            # Update URL usage
            url_usage = UserUrlUsage.query.filter_by(user_id=user_id).first()
            if url_usage:
                url_usage.urls_used += urls_analyzed
            else:
                url_usage = UserUrlUsage(user_id=user_id, urls_used=urls_analyzed)
                db.session.add(url_usage)

            # Mark job as complete
            job.status = "completed"
            job.progress = 100
            job.message = "Analysis complete"
            job.completed_at = datetime.utcnow()
            job.analysis_id = analysis.id
            db.session.commit()

            print(f"Analysis completed successfully. Analyzed {urls_analyzed} URLs.")
            return {
                "success": True,
                "analysis_id": analysis.id,
                "excel_file": saved_path,
                "urls_analyzed": urls_analyzed
            }

        except TaskAborted:
            # Expected cancellation path
            print(f"Job {job_id} was cancelled by user.")
            return {"status": "canceled", "message": "Cancelled by user"}
            
        except Exception as e:
            db.session.rollback()
            print("Error during analysis:", str(e))
            import traceback
            traceback.print_exc()
            job.status = "failed"
            job.message = str(e)
            job.completed_at = datetime.utcnow()
            db.session.commit()
            return {"error": str(e)}
            
        finally:
            # Clean up Redis cancellation flag if it exists
            r.delete(f"cancel_job:{job_id}")

@dramatiq.actor(time_limit=9600000, store_results=True)  
def analyze_selected_urls_task(user_id, job_id, max_urls, analyzed_urls_count):
    with app.app_context():
        r = redis.Redis.from_url(app.config['REDIS_URL'])
        
        job = AnalysisJob.query.get(job_id)
        if not job:
            return {"error": "Invalid job ID"}
        
        def check_cancellation():
            """Check if cancellation was requested"""
            if r.get(f"cancel_selected_job:{job_id}"):
                job.status = "canceled"
                job.message = "Cancelled by user"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                r.delete(f"cancel_selected_job:{job_id}")
                raise TaskAborted("Task cancelled by user")
        
        try:
            # Get selected URLs from Redis
            selected_data = r.get(f"selected_urls:{job_id}")
            if not selected_data:
                job.status = "failed"
                job.message = "No selected URLs found"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return {"error": "No selected URLs found"}
            
            data = json.loads(selected_data)
            urls_to_analyze = data.get('urls', [])
            sitemap_url = data.get('sitemap_url', '')
            original_url = data.get('original_url', '')
            
            if not urls_to_analyze:
                job.status = "failed"
                job.message = "No URLs to analyze"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return {"error": "No URLs to analyze"}
            
            print(f"Starting analysis of {len(urls_to_analyze)} selected URLs")
            
            # Initial setup
            job.status = "processing"
            job.started_at = datetime.utcnow()
            db.session.commit()
            
            # First cancellation check
            check_cancellation()
            
            # Parse the original URL to get domain
            from urllib.parse import urlparse
            parsed_original_url = urlparse(original_url)
            domain = parsed_original_url.netloc
            
            # Get configuration values
            moz_access_id = app.config.get("MOZ_ACCESS_ID", "")
            moz_secret_key = app.config.get("MOZ_SECRET_KEY", "")
            
            # Fetch Moz metrics for the domain
            check_cancellation()
            job.progress = 10
            job.message = "Fetching Moz metrics"
            db.session.commit()
            
            moz_metrics = {}
            try:
                moz_metrics = fetch_moz_metrics(original_url, moz_access_id, moz_secret_key)
                if moz_metrics:
                    moz_metrics["Spam Score"] = f"{moz_metrics.get('Spam Score', 'N/A')}%"
                else:
                    moz_metrics = {
                        "Domain Authority": "N/A",
                        "Page Authority": "N/A", 
                        "Spam Score": "N/A",
                        "Backlink Domain": "N/A"
                    }
                print("Fetched Moz metrics")
            except Exception as e:
                print(f"Error fetching Moz metrics: {str(e)}")
                moz_metrics = {
                    "Domain Authority": "Error",
                    "Page Authority": "Error", 
                    "Spam Score": "Error",
                    "Backlink Domain": "Error"
                }
            
            # Initialize metrics dictionary
            metrics = {
                "URL": [], "Last Modified": [], "Meta Title": [], "Meta Title Character Count": [],
                "Meta Description": [], "Meta Description Character Count": [], "Word Count": [],
                "H1 Tags": [], "H2 Tags": [], "Canonical Tag": [], "Largest Image Name": [],
                "Largest Image Size (KB)": [], "Structured Data": [], "Internal Links": [],
                "External Links": [], "Performance Score (Desktop)": [], "First Contentful Paint (Desktop)": [],
                "Speed Index (Desktop)": [], "Time to Interactive (Desktop)": [], "First Meaningful Paint (Desktop)": [],
                "CLS Lighthouse (Desktop)": [], "LCP Lighthouse (Desktop)": [], "Performance Score (Mobile)": [],
                "First Contentful Paint (Mobile)": [], "Speed Index (Mobile)": [], "Time to Interactive (Mobile)": [],
                "First Meaningful Paint (Mobile)": [], "CLS Lighthouse (Mobile)": [], "LCP Lighthouse (Mobile)": [],
                "Broken Links": [], "Image Details": [], "Indexability": [], "Response Code": [],
                "Email Privacy Issues": [], "Flash Used": [], "iFrames Used": [], "Favicon Used": []
            }
            
            # URL analysis loop
            total_urls = len(urls_to_analyze)
            urls_analyzed = 0
            
            for index, url in enumerate(urls_to_analyze):
                check_cancellation()
                
                print(f"Analyzing URL {index + 1}/{total_urls}: {url}")
                
                # Update progress
                progress = 20 + ((index + 1) / total_urls) * 70
                job.progress = int(progress)
                job.message = f"Analyzing URL {index + 1}/{total_urls}: {url}"
                db.session.commit()
                
                # Analyze page
                check_cancellation()
                try:
                    seo_metrics = analyze_page(url)
                    if not seo_metrics:
                        print(f"Skipping {url} - no metrics returned")
                        continue
                except Exception as e:
                    print(f"Error analyzing page {url}: {str(e)}")
                    continue
                
                # Fetch performance metrics
                check_cancellation()
                try:
                    desktop_metrics, mobile_metrics = fetch_pagespeed_metrics_lighthouse(url)
                except Exception as e:
                    print(f"Error fetching performance metrics: {str(e)}")
                    desktop_metrics = {
                        "Performance Score": "Error",
                        "First Contentful Paint": "Error",
                        "Speed Index": "Error",
                        "Time to Interactive": "Error",
                        "CLS Lighthouse": "Error",
                        "LCP Lighthouse": "Error"
                    }
                    mobile_metrics = desktop_metrics.copy()
                
                # Append metrics to dictionary
                append_metrics_to_dict(metrics, url, "N/A", seo_metrics, desktop_metrics, mobile_metrics, sitemap_url, moz_metrics)
                urls_analyzed += 1
            
            # Final report generation
            check_cancellation()
            job.progress = 95
            job.message = "Generating report"
            db.session.commit()
            
            check_cancellation()
            reports_dir = os.path.join(app.root_path, "analysis_reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            domain_name = domain.replace("www.", "").replace(".", "_")
            filename = f"seo_analysis_selected_{domain_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            excel_path = os.path.join(reports_dir, get_unique_filename(filename))
            
            # Save metrics to Excel
            saved_path = save_metrics_to_excel(metrics, sitemap_url, moz_metrics, excel_path)
            if not saved_path:
                job.status = "failed"
                job.message = "Failed to generate report"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return {"error": "Failed to create Excel file"}
            
            # Calculate grade (use first URL's metrics as sample)
            grade = "B"  # Default grade for bulk analysis
            if metrics.get("URL") and len(metrics["URL"]) > 0:
                # Try to get metrics from first analyzed URL
                try:
                    first_seo_metrics = {
                        "Meta Title Character Count": metrics["Meta Title Character Count"][0] if metrics["Meta Title Character Count"] else 0,
                        "Meta Description Character Count": metrics["Meta Description Character Count"][0] if metrics["Meta Description Character Count"] else 0,
                        "H1 Tags": metrics["H1 Tags"][0] if metrics["H1 Tags"] else "N/A",
                        "Canonical Tag": metrics["Canonical Tag"][0] if metrics["Canonical Tag"] else "N/A",
                        "Largest Image Size (KB)": metrics["Largest Image Size (KB)"][0] if metrics["Largest Image Size (KB)"] else "N/A",
                        "Structured Data": metrics["Structured Data"][0] if metrics["Structured Data"] else "No",
                        "Internal Links": metrics["Internal Links"][0] if metrics["Internal Links"] else 0,
                        "Word Count": metrics["Word Count"][0] if metrics["Word Count"] else 0
                    }
                    
                    first_desktop_metrics = {
                        "Performance Score": metrics["Performance Score (Desktop)"][0] if metrics["Performance Score (Desktop)"] else "N/A"
                    }
                    
                    first_mobile_metrics = {
                        "Performance Score": metrics["Performance Score (Mobile)"][0] if metrics["Performance Score (Mobile)"] else "N/A"
                    }
                    
                    grade = calculate_grade(first_seo_metrics, first_desktop_metrics, first_mobile_metrics, moz_metrics)
                except Exception as e:
                    print(f"Error calculating grade: {str(e)}")
            
            # Save analysis to database
            analysis = Analysis(
                website_name=domain,
                url=sitemap_url,
                excel_file=saved_path,
                user_id=user_id,
                grade=grade,
                moz_metrics=moz_metrics,
                metrics=metrics
            )
            db.session.add(analysis)
            db.session.flush()
            
            # Update URL usage
            url_usage = UserUrlUsage.query.filter_by(user_id=user_id).first()
            if url_usage:
                url_usage.urls_used += urls_analyzed
            else:
                url_usage = UserUrlUsage(user_id=user_id, urls_used=urls_analyzed)
                db.session.add(url_usage)
            
            # Mark job as complete
            job.status = "completed"
            job.progress = 100
            job.message = f"Analysis complete - {urls_analyzed} URLs analyzed"
            job.completed_at = datetime.utcnow()
            job.analysis_id = analysis.id
            db.session.commit()
            
            print(f"Analysis completed successfully. Analyzed {urls_analyzed} URLs.")
            return {
                "success": True,
                "analysis_id": analysis.id,
                "excel_file": saved_path,
                "urls_analyzed": urls_analyzed
            }
            
        except TaskAborted:
            print(f"Job {job_id} was cancelled by user.")
            return {"status": "canceled", "message": "Cancelled by user"}
            
        except Exception as e:
            db.session.rollback()
            print(f"Error during selected URL analysis: {str(e)}")
            import traceback
            traceback.print_exc()
            job.status = "failed"
            job.message = str(e)
            job.completed_at = datetime.utcnow()
            db.session.commit()
            return {"error": str(e)}
            
        finally:
            # Clean up Redis cancellation flag if it exists
            r.delete(f"cancel_job:{job_id}")

"""@dramatiq.actor(time_limit=9600000, store_results=True)  
def analyze_selected_urls_task(user_id, job_id, max_urls, analyzed_urls_count):
    with app.app_context():
        r = redis.Redis.from_url(app.config['REDIS_URL'])
        
        job = AnalysisJob.query.get(job_id)
        if not job:
            return {"error": "Invalid job ID"}
        
        def check_cancellation():
            ""Check if cancellation was requested""
            if r.get(f"cancel_selected_job:{job_id}"):
                job.status = "canceled"
                job.message = "Cancelled by user"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                r.delete(f"cancel_selected_job:{job_id}")
                raise TaskAborted("Task cancelled by user")
        
        def update_progress(progress, message):
            ""Update progress in both database and Redis""
            job.progress = progress
            job.message = message
            db.session.commit()
            
            # Also update Redis for SSE endpoint
            r.setex(f"selected_urls_job:{job_id}", 3600, json.dumps({
                "status": job.status,
                "progress": progress,
                "message": message,
                "updated_at": datetime.utcnow().isoformat(),
                "user_id": user_id,
                "job_id": job_id
            }))
        
        try:
            # Get selected URLs from Redis
            selected_data = r.get(f"selected_urls:{job_id}")
            if not selected_data:
                job.status = "failed"
                job.message = "No selected URLs found"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return {"error": "No selected URLs found"}
            
            data = json.loads(selected_data)
            urls_to_analyze = data.get('urls', [])
            sitemap_url = data.get('sitemap_url', '')
            original_url = data.get('original_url', '')
            
            if not urls_to_analyze:
                job.status = "failed"
                job.message = "No URLs to analyze"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return {"error": "No URLs to analyze"}
            
            print(f"Starting analysis of {len(urls_to_analyze)} selected URLs")
            
            # Initial setup
            job.status = "processing"
            job.started_at = datetime.utcnow()
            db.session.commit()
            
            # Update initial progress
            update_progress(5, "Starting selected URLs analysis...")
            
            # First cancellation check
            check_cancellation()
            
            # Parse the original URL to get domain
            from urllib.parse import urlparse
            parsed_original_url = urlparse(original_url)
            domain = parsed_original_url.netloc
            
            # Get configuration values
            moz_access_id = app.config.get("MOZ_ACCESS_ID", "")
            moz_secret_key = app.config.get("MOZ_SECRET_KEY", "")
            
            # Fetch Moz metrics for the domain
            check_cancellation()
            update_progress(10, "Fetching Moz metrics...")
            
            moz_metrics = {}
            try:
                moz_metrics = fetch_moz_metrics(original_url, moz_access_id, moz_secret_key)
                if moz_metrics:
                    moz_metrics["Spam Score"] = f"{moz_metrics.get('Spam Score', 'N/A')}%"
                else:
                    moz_metrics = {
                        "Domain Authority": "N/A",
                        "Page Authority": "N/A", 
                        "Spam Score": "N/A",
                        "Backlink Domain": "N/A"
                    }
                print("Fetched Moz metrics")
            except Exception as e:
                print(f"Error fetching Moz metrics: {str(e)}")
                moz_metrics = {
                    "Domain Authority": "Error",
                    "Page Authority": "Error", 
                    "Spam Score": "Error",
                    "Backlink Domain": "Error"
                }
            
            # Initialize metrics dictionary
            metrics = {
                "URL": [], "Last Modified": [], "Meta Title": [], "Meta Title Character Count": [],
                "Meta Description": [], "Meta Description Character Count": [], "Word Count": [],
                "H1 Tags": [], "H2 Tags": [], "Canonical Tag": [], "Largest Image Name": [],
                "Largest Image Size (KB)": [], "Structured Data": [], "Internal Links": [],
                "External Links": [], "Performance Score (Desktop)": [], "First Contentful Paint (Desktop)": [],
                "Speed Index (Desktop)": [], "Time to Interactive (Desktop)": [], "First Meaningful Paint (Desktop)": [],
                "CLS Lighthouse (Desktop)": [], "LCP Lighthouse (Desktop)": [], "Performance Score (Mobile)": [],
                "First Contentful Paint (Mobile)": [], "Speed Index (Mobile)": [], "Time to Interactive (Mobile)": [],
                "First Meaningful Paint (Mobile)": [], "CLS Lighthouse (Mobile)": [], "LCP Lighthouse (Mobile)": [],
                "Broken Links": [], "Image Details": [], "Indexability": [], "Response Code": [],
                "Email Privacy Issues": [], "Flash Used": [], "iFrames Used": [], "Favicon Used": []
            }
            
            # URL analysis loop
            total_urls = len(urls_to_analyze)
            urls_analyzed = 0
            
            # Calculate progress range: 20% for setup, 70% for URL analysis, 10% for finalization
            setup_progress = 20
            url_analysis_progress = 70
            final_progress = 10
            
            update_progress(setup_progress, f"Preparing to analyze {total_urls} URLs...")
            
            for index, url in enumerate(urls_to_analyze):
                check_cancellation()
                
                # Format URL for display (truncate if too long)
                display_url = url
                if len(url) > 80:
                    display_url = url[:77] + "..."
                
                print(f"Analyzing URL {index + 1}/{total_urls}: {url}")
                
                # Update progress - CRITICAL: Make sure message includes full URL for extraction
                progress = setup_progress + ((index + 1) / total_urls) * url_analysis_progress
                
                # Use a format that the SSE endpoint can parse for current URL
                message = f"Analyzing URL {index + 1} of {total_urls}: {url}"
                update_progress(int(progress), message)
                
                # Analyze page
                check_cancellation()
                try:
                    seo_metrics = analyze_page(url)
                    if not seo_metrics:
                        print(f"Skipping {url} - no metrics returned")
                        continue
                except Exception as e:
                    print(f"Error analyzing page {url}: {str(e)}")
                    continue
                
                # Fetch performance metrics
                check_cancellation()
                try:
                    desktop_metrics, mobile_metrics = fetch_pagespeed_metrics_lighthouse(url)
                except Exception as e:
                    print(f"Error fetching performance metrics: {str(e)}")
                    desktop_metrics = {
                        "Performance Score": "Error",
                        "First Contentful Paint": "Error",
                        "Speed Index": "Error",
                        "Time to Interactive": "Error",
                        "CLS Lighthouse": "Error",
                        "LCP Lighthouse": "Error"
                    }
                    mobile_metrics = desktop_metrics.copy()
                
                # Append metrics to dictionary
                append_metrics_to_dict(metrics, url, "N/A", seo_metrics, desktop_metrics, mobile_metrics, sitemap_url, moz_metrics)
                urls_analyzed += 1
            
            # Final report generation
            check_cancellation()
            update_progress(95, "Generating report and saving results...")
            
            check_cancellation()
            reports_dir = os.path.join(app.root_path, "analysis_reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            domain_name = domain.replace("www.", "").replace(".", "_")
            filename = f"seo_analysis_selected_{domain_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            excel_path = os.path.join(reports_dir, get_unique_filename(filename))
            
            # Save metrics to Excel
            saved_path = save_metrics_to_excel(metrics, sitemap_url, moz_metrics, excel_path)
            if not saved_path:
                job.status = "failed"
                job.message = "Failed to generate report"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return {"error": "Failed to create Excel file"}
            
            # Calculate grade (use first URL's metrics as sample)
            grade = "B"  # Default grade for bulk analysis
            if metrics.get("URL") and len(metrics["URL"]) > 0:
                # Try to get metrics from first analyzed URL
                try:
                    first_seo_metrics = {
                        "Meta Title Character Count": metrics["Meta Title Character Count"][0] if metrics["Meta Title Character Count"] else 0,
                        "Meta Description Character Count": metrics["Meta Description Character Count"][0] if metrics["Meta Description Character Count"] else 0,
                        "H1 Tags": metrics["H1 Tags"][0] if metrics["H1 Tags"] else "N/A",
                        "Canonical Tag": metrics["Canonical Tag"][0] if metrics["Canonical Tag"] else "N/A",
                        "Largest Image Size (KB)": metrics["Largest Image Size (KB)"][0] if metrics["Largest Image Size (KB)"][0] else "N/A",
                        "Structured Data": metrics["Structured Data"][0] if metrics["Structured Data"] else "No",
                        "Internal Links": metrics["Internal Links"][0] if metrics["Internal Links"] else 0,
                        "Word Count": metrics["Word Count"][0] if metrics["Word Count"] else 0
                    }
                    
                    first_desktop_metrics = {
                        "Performance Score": metrics["Performance Score (Desktop)"][0] if metrics["Performance Score (Desktop)"][0] else "N/A"
                    }
                    
                    first_mobile_metrics = {
                        "Performance Score": metrics["Performance Score (Mobile)"][0] if metrics["Performance Score (Mobile)"][0] else "N/A"
                    }
                    
                    grade = calculate_grade(first_seo_metrics, first_desktop_metrics, first_mobile_metrics, moz_metrics)
                except Exception as e:
                    print(f"Error calculating grade: {str(e)}")
            
            # Save analysis to database
            analysis = Analysis(
                website_name=domain,
                url=sitemap_url,
                excel_file=saved_path,
                user_id=user_id,
                grade=grade,
                moz_metrics=moz_metrics,
                metrics=metrics
            )
            db.session.add(analysis)
            db.session.flush()
            
            # Update URL usage
            url_usage = UserUrlUsage.query.filter_by(user_id=user_id).first()
            if url_usage:
                url_usage.urls_used += urls_analyzed
            else:
                url_usage = UserUrlUsage(user_id=user_id, urls_used=urls_analyzed)
                db.session.add(url_usage)
            
            # Mark job as complete
            job.status = "completed"
            job.progress = 100
            job.message = f"Analysis complete - {urls_analyzed} URLs analyzed"
            job.completed_at = datetime.utcnow()
            job.analysis_id = analysis.id
            db.session.commit()
            
            # Update final status in Redis
            r.setex(f"selected_urls_job:{job_id}", 3600, json.dumps({
                "status": "completed",
                "progress": 100,
                "message": f"Analysis complete - {urls_analyzed} URLs analyzed",
                "analysis_id": analysis.id,
                "download_url": f"/download/{analysis.id}",
                "updated_at": datetime.utcnow().isoformat()
            }))
            
            print(f"Analysis completed successfully. Analyzed {urls_analyzed} URLs.")
            return {
                "success": True,
                "analysis_id": analysis.id,
                "excel_file": saved_path,
                "urls_analyzed": urls_analyzed
            }
            
        except TaskAborted:
            print(f"Job {job_id} was cancelled by user.")
            
            # Update cancellation status in Redis
            r.setex(f"selected_urls_job:{job_id}", 3600, json.dumps({
                "status": "canceled",
                "progress": job.progress,
                "message": "Cancelled by user",
                "updated_at": datetime.utcnow().isoformat()
            }))
            
            return {"status": "canceled", "message": "Cancelled by user"}
            
        except Exception as e:
            db.session.rollback()
            print(f"Error during selected URL analysis: {str(e)}")
            import traceback
            traceback.print_exc()
            
            job.status = "failed"
            job.message = str(e)
            job.completed_at = datetime.utcnow()
            db.session.commit()
            
            # Update error status in Redis
            r.setex(f"selected_urls_job:{job_id}", 3600, json.dumps({
                "status": "failed",
                "progress": 100,
                "message": f"Error: {str(e)}",
                "updated_at": datetime.utcnow().isoformat()
            }))
            
            return {"error": str(e)}
            
        finally:
            # Clean up Redis cancellation flag if it exists
            try:
                r.delete(f"cancel_selected_job:{job_id}")
            except:
                pass"""


@dramatiq.actor(max_retries=0)
def analyze_single_url_task(url, job_id, user_id=None):
    """
    Optimized single URL analysis with parallel heavy tasks.

    KEY OPTIMISATION vs original:
      • get_performance_metrics, analyze_page, and capture_device_screenshots
        all run concurrently in a ThreadPoolExecutor (unchanged from your
        current version — kept as-is since it was already parallelised).
      • All lightweight checks (Moz, keywords, robots, SSL, hreflang, schema,
        analytics, Google update) also run concurrently.
      • Screenshots are still fetched in parallel but will NOT block the
        performance or SEO metrics from completing.
    """
    try:
        with app.app_context():
            # ── Job init ─────────────────────────────────────────────────────
            single_job = SingleUrlJob.query.get(job_id)
            if single_job:
                single_job.status = "processing"
                single_job.started_at = datetime.utcnow()
                single_job.progress = 5
                single_job.message = "Starting analysis..."
                db.session.commit()

            # ── Read sitemap metadata pre-populated by main.py ───────────────
            # main.py's find_url_in_sitemap() already ran before this task was
            # queued. Load what it stored so we can (a) show the user a status
            # badge, and (b) use the sitemap's lastmod date if available.
            _sitemap_meta = {}
            try:
                _existing = redis_conn.get(f"single_url_job:{job_id}")
                if _existing:
                    _sitemap_meta = json.loads(_existing)
            except Exception:
                pass

            _sitemap_url     = _sitemap_meta.get("sitemap_url")
            _sitemap_status  = _sitemap_meta.get("sitemap_status", "not_checked")
            _sitemap_warning = _sitemap_meta.get("sitemap_warning")
            _last_modified   = "N/A"   # will be populated below if found in sitemap

            def _redis_update(progress, message):
                redis_conn.setex(f"single_url_job:{job_id}", 3600, json.dumps({
                    "url": url,
                    "status": "processing",
                    "progress": progress,
                    "message": message,
                    "updated_at": datetime.utcnow().isoformat(),
                    "user_id": user_id,
                    # Carry sitemap fields through every progress update
                    "sitemap_url":     _sitemap_url,
                    "sitemap_status":  _sitemap_status,
                    "sitemap_warning": _sitemap_warning,
                }))
                if single_job:
                    single_job.progress = progress
                    single_job.message = message
                    db.session.commit()

            _redis_update(5, "Starting analysis...")

            # ── Validate URL ─────────────────────────────────────────────────
            if not is_valid_url(url):
                raise ValueError("Invalid URL format")

            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            domain = parsed_url.netloc

            # ── Sitemap crawl: confirm URL & grab lastmod ─────────────────────
            # If main.py already confirmed the URL was found in the sitemap we
            # still crawl here (inside the task) to grab the lastmod date.
            # If the pre-check was skipped or failed we re-run the full lookup.
            _redis_update(8, "Checking sitemap for this URL...")
            try:
                if _sitemap_status in ("not_checked", "sitemap_error"):
                    # Re-run the full lookup inside the task
                    _sr = check_url_in_sitemap(url)
                    _sitemap_url     = _sr.get("sitemap_url")
                    _sitemap_status  = "found_in_sitemap" if _sr.get("found") else "not_in_sitemap"
                    _sitemap_warning = _sr.get("error")

                # Fetch lastmod from the sitemap XML for this specific URL
                if _sitemap_url and _sitemap_status == "found_in_sitemap":
                    import xml.etree.ElementTree as _ET
                    import requests as _req
                    _ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                    _resp = _req.get(_sitemap_url, timeout=15)
                    _root = _ET.fromstring(_resp.content)
                    _target_norm = url.rstrip("/").lower()
                    for _entry in _root.findall('.//sm:url', _ns):
                        _loc_el = _entry.find('sm:loc', _ns)
                        if _loc_el is not None and _loc_el.text.rstrip("/").lower() == _target_norm:
                            _lm = _entry.find('sm:lastmod', _ns)
                            if _lm is not None and _lm.text:
                                _last_modified = _lm.text.strip()
                            break
            except Exception as _e:
                print(f"[single-url task] Sitemap crawl error (non-fatal): {_e}")

            print(
                f"[single-url task] sitemap_status={_sitemap_status} | "
                f"lastmod={_last_modified} | sitemap={_sitemap_url}"
            )

            # ── Fetch HTML (required before lightweight checks) ───────────────
            _redis_update(10, "Mapping out your digital footprint...")
            html_content = fetch_html(url)
            if not html_content:
                raise Exception("Failed to fetch HTML content")

            
            _redis_update(15, "Every masterpiece begins with a single scan...")

            results = {}
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_performance = executor.submit(get_performance_metrics, url)
                future_analyze = executor.submit(analyze_page, url)
                future_screenshots = executor.submit(capture_device_screenshots, url)

                heavy_tasks = {
                    future_performance: "performance",
                    future_analyze: "analyze",
                    future_screenshots: "screenshots",
                }

                completed = 0
                for future in as_completed(heavy_tasks):
                    task_name = heavy_tasks[future]
                    try:
                        if task_name == "performance":
                            results['performance_data'] = future.result(timeout=180)
                        elif task_name == "analyze":
                            results['seo_metrics'] = future.result(timeout=120)
                        elif task_name == "screenshots":
                            results['screenshots'] = future.result(timeout=120) or {}
                    except Exception as e:
                        print(f"Heavy task '{task_name}' error: {e}")
                        results[task_name] = {}

                    completed += 1
                    progress = 20 + int((completed / 3) * 40)  # 20 → 60%
                    _redis_update(progress, f"Tuning your engine for the fast lane...")

            # ── PHASE 2: Run ALL lightweight tasks in parallel ────────────────
            # These are all network/CPU-light and can all fire simultaneously.
            _redis_update(80, "Gathering the building blocks of success...")

            with ThreadPoolExecutor(max_workers=8) as executor:

                def task_moz():
                    moz_id = app.config.get("MOZ_ACCESS_ID", "")
                    moz_sk = app.config.get("MOZ_SECRET_KEY", "")
                    if moz_id and moz_sk:
                        try:
                            return fetch_moz_metrics(url, moz_id, moz_sk)
                        except Exception:
                            pass
                    try:
                        return fetch_open_pagerank_metrics(domain)
                    except Exception:
                        return {"Domain Authority": "N/A", "Page Authority": "N/A",
                                "Spam Score": "N/A", "Backlink Domain": "N/A"}

                def task_keyword():
                    try:
                        analyzer = SimpleKeywordAnalyzer()
                        return analyzer.analyze_url_keywords(url)
                    except Exception as e:
                        print(f"Keyword error: {e}")
                        return {'extracted_keywords': [], 'keyword_suggestions': []}

                def task_robots_sitemap():
                    robots = check_robots_txt(base_url)
                    sitemap = guess_sitemap_url(base_url)
                    return {'robots': robots, 'sitemap': sitemap}

                def task_ssl():
                    return check_ssl_certificate(domain)

                def task_hreflang():
                    return check_hreflang(html_content)

                def task_schema():
                    return check_schema_markup(html_content)

                def task_analytics():
                    return detect_analytics(html_content)

                def task_google_update():
                    return fetch_latest_google_update()

                future_moz = executor.submit(task_moz)
                future_keyword = executor.submit(task_keyword)
                future_robots = executor.submit(task_robots_sitemap)
                future_ssl = executor.submit(task_ssl)
                future_hreflang = executor.submit(task_hreflang)
                future_schema = executor.submit(task_schema)
                future_analytics = executor.submit(task_analytics)
                future_update = executor.submit(task_google_update)

                moz_metrics = future_moz.result(timeout=30)
                keyword_analysis = future_keyword.result(timeout=30)
                robots_sitemap = future_robots.result(timeout=30)
                ssl_info = future_ssl.result(timeout=30)
                hreflang_tags = future_hreflang.result(timeout=30)
                schema_types = future_schema.result(timeout=30)
                analytics_results = future_analytics.result(timeout=30)
                latest_update = future_update.result(timeout=30)

            # ── Extract results from heavy phase ─────────────────────────────
            performance_data = results.get('performance_data', {})
            seo_metrics = results.get('seo_metrics', {})
            screenshots = results.get('screenshots', {})
            # Get ALL performance data from Lighthouse - SINGLE CALL
            #performance_data = get_performance_metrics(url)
            
            # Extract desktop and mobile metrics from the single performance_data
            desktop_metrics = {
                "Performance Score": performance_data.get("Performance Score (Desktop)", "N/A"),
                "First Contentful Paint": performance_data.get("First Contentful Paint (Desktop)", "N/A"),
                "Speed Index": performance_data.get("Speed Index (Desktop)", "N/A"),
                "Time to Interactive": performance_data.get("Time to Interactive (Desktop)", "N/A"),
                "CLS Lighthouse": performance_data.get("CLS Lighthouse (Desktop)", "N/A"),
                "LCP Lighthouse": performance_data.get("LCP Lighthouse (Desktop)", "N/A")
            }

            mobile_metrics = {
                "Performance Score": performance_data.get("Performance Score (Mobile)", "N/A"),
                "First Contentful Paint": performance_data.get("First Contentful Paint (Mobile)", "N/A"),
                "Speed Index": performance_data.get("Speed Index (Mobile)", "N/A"),
                "Time to Interactive": performance_data.get("Time to Interactive (Mobile)", "N/A"),
                "CLS Lighthouse": performance_data.get("CLS Lighthouse (Mobile)", "N/A"),
                "LCP Lighthouse": performance_data.get("LCP Lighthouse (Mobile)", "N/A")
            }
            
            # Create performance_metrics from the same performance_data
            performance_metrics = {
                "Server Response Time": performance_data.get("Server Response Time", "N/A"),
                "All Content Loaded Time": performance_data.get("All Content Loaded Time", "N/A"),
                "Scripts Complete Time": performance_data.get("Scripts Complete Time", "N/A"),
                "Total Page Size (MB)": performance_data.get("Total Page Size (MB)", "N/A"),
                "HTML Size (MB)": performance_data.get("HTML Size (MB)", "N/A"),
                "CSS Size (MB)": performance_data.get("CSS Size (MB)", "N/A"),
                "JS Size (MB)": performance_data.get("JS Size (MB)", "N/A"),
                "Image Size (MB)": performance_data.get("Image Size (MB)", "N/A"),
                "Other Size (MB)": performance_data.get("Other Size (MB)", "N/A"),
                "HTML Decoded Size (MB)": performance_data.get("HTML Decoded Size (MB)", "N/A"),
                "CSS Decoded Size (MB)": performance_data.get("CSS Decoded Size (MB)", "N/A"),
                "JS Decoded Size (MB)": performance_data.get("JS Decoded Size (MB)", "N/A"),
                "Image Decoded Size (MB)": performance_data.get("Image Decoded Size (MB)", "N/A"),
                "Other Decoded Size (MB)": performance_data.get("Other Decoded Size (MB)", "N/A")
            }
            # Debug print to verify data is being collected
            print(f"DEBUG: Performance metrics collected - Total Page Size: {performance_metrics.get('Total Page Size (MB)')}")
            print(f"DEBUG: Performance metrics keys: {list(performance_metrics.keys())}")

            # ── Extract additional SEO metric fields ──────────────────────────
            robots_info = robots_sitemap.get('robots', {})
            sitemap_info = robots_sitemap.get('sitemap', {})
            images_without_alt = count_images_without_alt(seo_metrics.get('Image Details', []))
            js_errors_list = seo_metrics.get("JS Errors", [])
            responsive_image_issues_list = seo_metrics.get("Responsive Image Issues", [])
            charset_declared = seo_metrics.get("Charset Declared", "No")
            charset_value = seo_metrics.get("Charset", "Not declared")
            js_errors_count = len(js_errors_list) if isinstance(js_errors_list, list) else 0
            responsive_issues_count = len(responsive_image_issues_list) if isinstance(responsive_image_issues_list, list) else 0

            # ── Recommendations + grade ───────────────────────────────────────
            _redis_update(90, "Putting the finishing touches on your success story...")
            recommendations = generate_recommendations(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics)
            grade_results = singlepage_grade(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics)

            # ── Build final metrics dict ──────────────────────────────────────
            _redis_update(95, "Another website ready to conquer the search engines..")
            metrics = {
                "URL": [url],
                "Last Modified": [_last_modified],  # from sitemap lastmod if found
                "Meta Title": [seo_metrics.get("Meta Title", "N/A")],
                "Meta Title Character Count": [seo_metrics.get("Meta Title Character Count", 0)],
                "Meta Description": [seo_metrics.get("Meta Description", "N/A")],
                "Meta Description Character Count": [seo_metrics.get("Meta Description Character Count", 0)],
                "Word Count": [seo_metrics.get("Word Count", 0)],
                "H1 Tags": [seo_metrics.get("H1 Tags", "N/A")],
                "H2 Tags": [seo_metrics.get("H2 Tags", "N/A")],
                "H3 Tags": [seo_metrics.get("H3 Tags", "N/A")],
                "H4 Tags": [seo_metrics.get("H4 Tags", "N/A")],
                "H5 Tags": [seo_metrics.get("H5 Tags", "N/A")],
                "H6 Tags": [seo_metrics.get("H6 Tags", "N/A")],
                "Canonical Tag": [seo_metrics.get("Canonical Tag", "N/A")],
                "Largest Image Name": [seo_metrics.get("Largest Image Name", "N/A")],
                "Largest Image Size (KB)": [seo_metrics.get("Largest Image Size (KB)", "N/A")],
                "Structured Data": [seo_metrics.get("Structured Data", "No")],
                "Internal Links": [seo_metrics.get("Internal Links", 0)],
                "External Links": [seo_metrics.get("External Links", 0)],
                "Performance Score (Desktop)": [desktop_metrics.get('Performance Score', 'N/A')],
                "First Contentful Paint (Desktop)": [desktop_metrics.get('First Contentful Paint', 'N/A')],
                "Speed Index (Desktop)": [desktop_metrics.get('Speed Index', 'N/A')],
                "Time to Interactive (Desktop)": [desktop_metrics.get('Time to Interactive', 'N/A')],
                "CLS Lighthouse (Desktop)": [desktop_metrics.get('CLS Lighthouse', 'N/A')],
                "LCP Lighthouse (Desktop)": [desktop_metrics.get('LCP Lighthouse', 'N/A')],
                "Performance Score (Mobile)": [mobile_metrics.get('Performance Score', 'N/A')],
                "First Contentful Paint (Mobile)": [mobile_metrics.get('First Contentful Paint', 'N/A')],
                "Speed Index (Mobile)": [mobile_metrics.get('Speed Index', 'N/A')],
                "Time to Interactive (Mobile)": [mobile_metrics.get('Time to Interactive', 'N/A')],
                "CLS Lighthouse (Mobile)": [mobile_metrics.get('CLS Lighthouse', 'N/A')],
                "LCP Lighthouse (Mobile)": [mobile_metrics.get('LCP Lighthouse', 'N/A')],
                "Broken Links": [seo_metrics.get("Broken Links", "N/A")],
                "Image Details": [seo_metrics.get("Image Details", [])],
                "Indexability": [seo_metrics.get("Indexability", "Unknown")],
                "Response Code": [seo_metrics.get("Response Code", "Error")],
                "Email Privacy Issues": [", ".join(seo_metrics.get("Email Privacy Issues", ["None"]))],
                "Flash Used": [seo_metrics.get("Flash Used", "No")],
                "iFrames Used": [seo_metrics.get("iFrames Used", "No")],
                "Favicon Used": [seo_metrics.get("Favicon Used", "No")],
                "Domain Authority": [moz_metrics.get("Domain Authority", "N/A")],
                "Page Authority": [moz_metrics.get("Page Authority", "N/A")],
                "Spam Score": [moz_metrics.get("Spam Score", "N/A")],
                "Link Propensity": [moz_metrics.get("Link Propensity", "N/A")],
                "Total Backlinks": [moz_metrics.get("Total Backlinks", "N/A")],
                "Backlink Domain": [moz_metrics.get("Backlink Domain", "N/A")],
                "Server Response Time": [performance_metrics.get("Server Response Time", "N/A")],
                "All Content Loaded Time": [performance_metrics.get("All Content Loaded Time", "N/A")],
                "Scripts Complete Time": [performance_metrics.get("Scripts Complete Time", "N/A")],
                "Total Page Size (MB)": [performance_metrics.get("Total Page Size (MB)", "N/A")],
                "Total Transfer Size (MB)": [performance_metrics.get("Total Transfer Size (MB)", 0)],
                "HTML Size (MB)": [performance_metrics.get("HTML Size (MB)", "N/A")],
                "CSS Size (MB)": [performance_metrics.get("CSS Size (MB)", "N/A")],
                "JS Size (MB)": [performance_metrics.get("JS Size (MB)", "N/A")],
                "Image Size (MB)": [performance_metrics.get("Image Size (MB)", "N/A")],
                "Other Size (MB)": [performance_metrics.get("Other Size (MB)", "N/A")],
                "Robots.txt": [robots_info.get('robots_url', 'Not found') if robots_info.get('exists') else "Not found"],
                "Sitemap.xml": [sitemap_info.get('sitemap_url', 'Not found') if sitemap_info.get('exists') else "Not found"],
                "Disallowed Paths": [", ".join(robots_info.get('disallowed_paths', [])) or "None"],
                "Hreflang Tags": [len(hreflang_tags) if hreflang_tags else "None"],
                "Schema Types": [", ".join(schema_types) if schema_types else "None"],
                "SSL Enabled": ["Yes" if ssl_info.get('has_ssl') else "No"],
                "SSL Expiry Date": [ssl_info.get('expiry_date', 'N/A')],
                "Images Without Alt": [images_without_alt],
                "GA4 (gtag.js)": [analytics_results.get("GA4 (gtag.js)", "N/A")],
                "Universal Analytics (analytics.js)": [analytics_results.get("Universal Analytics (analytics.js)", "N/A")],
                "Google Tag Manager (GTM)": [analytics_results.get("Google Tag Manager (GTM)", "N/A")],
                "Responsive Image Issues": [responsive_issues_count],
                "JS Errors": [js_errors_count],
                "Charset Declared": [charset_declared],
                "Charset": [charset_value],
            }

            # ── Build final result payload ─────────────────────────────────
            result = {
                "success": True,
                "metrics": metrics,
                "grade": grade_results['overall'],
                "weighted_score": grade_results['weighted_score'],
                "category_grades": grade_results['categories'],
                "recommendations": recommendations,
                "hreflang_tags": hreflang_tags,
                "keyword_analysis": keyword_analysis,
                "schema_types": schema_types,
                "ssl_info": ssl_info,
                "images_without_alt": images_without_alt,
                "performance_metrics": performance_metrics,
                "screenshots": screenshots,
                "latest_update": latest_update,
                "responsive_image_issues_details": responsive_image_issues_list,
                "js_errors_details": js_errors_list,
                "charset_info": {
                    "declared": charset_declared == "Yes",
                    "charset": charset_value,
                    "issues": seo_metrics.get("Charset Issues", [])
                },
                # ── Sitemap verification metadata ──────────────────────────
                "sitemap_url":     _sitemap_url,
                "sitemap_status":  _sitemap_status,   # found_in_sitemap | not_in_sitemap | sitemap_error | not_checked
                "sitemap_warning": _sitemap_warning,
            }

            # ── Persist to DB + Redis ─────────────────────────────────────
            if single_job:
                single_job.status = "completed"
                single_job.progress = 100
                single_job.message = "Analysis complete!"
                single_job.completed_at = datetime.utcnow()
                single_job.results_data = result
                db.session.commit()

            redis_conn.setex(f"single_url_job:{job_id}", 3600, json.dumps({
                "url": url,
                "status": "completed",
                "progress": 100,
                "message": "Analysis complete!",
                "result": result,
                "updated_at": datetime.utcnow().isoformat(),
                "completed_at": datetime.utcnow().isoformat(),
                "user_id": user_id,
                # Sitemap fields at top level for easy frontend access
                "sitemap_url":     _sitemap_url,
                "sitemap_status":  _sitemap_status,
                "sitemap_warning": _sitemap_warning,
            }))

    except Exception as e:
        import traceback
        traceback.print_exc()
        with app.app_context():
            single_job = SingleUrlJob.query.get(job_id)
            if single_job:
                single_job.status = "failed"
                single_job.progress = 100
                single_job.message = f"Error: {str(e)}"
                single_job.completed_at = datetime.utcnow()
                single_job.error_message = str(e)
                db.session.commit()
        redis_conn.setex(f"single_url_job:{job_id}", 3600, json.dumps({
            "url": url,
            "status": "failed",
            "progress": 100,
            "message": f"System error: {str(e)}",
            "result": {"success": False, "error": str(e)},
            "updated_at": datetime.utcnow().isoformat()
        }))
