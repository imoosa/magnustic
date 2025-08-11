from urllib.parse import urlparse
from datetime import datetime
import os

from main import app, db
from main import AnalysisJob, Analysis, UserUrlUsage
from main import (
    fetch_moz_metrics,
    guess_sitemap_url,
    fetch_sitemap_urls,
    fetch_urls_from_sitemap,
    fetch_and_parse_sitemap,
    analyze_page,
    fetch_pagespeed_metrics,
    append_metrics_to_dict,
    calculate_grade,
    get_unique_filename,
    save_metrics_to_excel,
)

import dramatiq

import redis

# Custom exception for task cancellation
class TaskAborted(Exception):
    """Custom exception for aborted tasks"""
    pass

@dramatiq.actor(store_results=True, time_limit=9600000)
def analyze_sitemap_task(user_id, url, max_urls, analyzed_urls_count, job_id):
    with app.app_context():
        # Initialize Redis connection
        r = redis.from_url(app.config['REDIS_URL'])
        
        job = AnalysisJob.query.get(job_id)
        if not job:
            return {"error": "Invalid job ID"}

        def check_cancellation():
            """Check if cancellation was requested and handle it if so."""
            if r.get(f"cancel_job:{job_id}"):
                # Update job status in database
                job.status = "canceled"
                job.message = "Cancelled by user"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                
                # Clean up Redis key
                r.delete(f"cancel_job:{job_id}")
                
                # Raise custom exception to break out of processing
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
            google_api_key = app.config.get("GOOGLE_API_KEY", "")
            moz_access_id = app.config.get("MOZ_ACCESS_ID", "")
            moz_secret_key = app.config.get("MOZ_SECRET_KEY", "")

            # Sitemap discovery with cancellation check
            check_cancellation()
            print("Attempting to find the sitemap...")
            if url.endswith(".xml"):
                sitemap_url = url
            else:
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                sitemap_url = guess_sitemap_url(base_url)

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

            # Fetch Moz metrics with cancellation check
            moz_metrics = fetch_moz_metrics(domain, moz_access_id, moz_secret_key)
            moz_metrics["Spam Score"] = f"{moz_metrics.get('Spam Score', 'N/A')}%"
            print("Fetched Moz metrics")

            # Fetch URLs from sitemap with cancellation checks
            check_cancellation()
            sitemap_entries = fetch_sitemap_urls(sitemap_url) or []
            urls = []

            if sitemap_entries:
                for sitemap_entry, _ in sitemap_entries:
                    check_cancellation()
                    urls += fetch_urls_from_sitemap(sitemap_entry) or []
            else:
                check_cancellation()
                urls = fetch_and_parse_sitemap(sitemap_url) or []

            urls = urls[:max_urls - analyzed_urls_count]
            total_urls = len(urls)
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
                "Broken Links": [], "Image Details": []
            }

            # URL analysis loop with periodic cancellation checks
            urls_analyzed = 0
            for index, url in enumerate(urls):
                check_cancellation()  # Check at start of each iteration

                print(f"Analyzing URL {index + 1}/{total_urls}: {url}")

                # Update progress
                job.progress = 10 + ((index + 1) / total_urls) * 80
                job.message = f"Analyzing URL {index + 1}/{total_urls}: {url}"
                db.session.commit()

                # Analyze page with cancellation check
                check_cancellation()
                seo_metrics = analyze_page(url)
                if not seo_metrics:
                    continue

                # Fetch metrics with cancellation checks
                check_cancellation()
                desktop_metrics = fetch_pagespeed_metrics(url, "desktop", google_api_key)
                
                check_cancellation()
                mobile_metrics = fetch_pagespeed_metrics(url, "mobile", google_api_key)

                append_metrics_to_dict(metrics, url, "N/A", seo_metrics, desktop_metrics, mobile_metrics, sitemap_url, moz_metrics)
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

            saved_path = save_metrics_to_excel(metrics, sitemap_url, moz_metrics)
            if not saved_path:
                job.status = "failed"
                job.message = "Failed to generate report"
                job.completed_at = datetime.utcnow()
                db.session.commit()
                return {"error": "Failed to create Excel file"}

            # Calculate grade and save analysis
            check_cancellation()
            grade = calculate_grade(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics)

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

            # Mark job as complete
            job.status = "completed"
            job.progress = 100
            job.message = "Analysis complete"
            job.completed_at = datetime.utcnow()
            job.analysis_id = analysis.id
            db.session.commit()

            print("Analysis completed successfully.")
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
            job.status = "failed"
            job.message = str(e)
            job.completed_at = datetime.utcnow()
            db.session.commit()
            return {"error": str(e)}
            
        finally:
            # Clean up Redis cancellation flag if it exists
            r.delete(f"cancel_job:{job_id}")

