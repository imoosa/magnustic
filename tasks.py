from app import celery, db
from app import app
from your_analysis_functions import (
    fetch_sitemap_urls,
    analyze_page,
    fetch_pagespeed_metrics,
    save_metrics_to_excel,
    calculate_grade
)
import time

@celery.task(bind=True)
def analyze_task(self, url, user_id):
    try:
        # Initialize progress tracking
        self.update_state(state='PROGRESS', meta={'progress': 0, 'status': 'Starting analysis'})
        
        # Step 1: Find sitemap
        self.update_state(state='PROGRESS', meta={'progress': 10, 'status': 'Locating sitemap'})
        sitemap_url = guess_sitemap_url(url)
        
        # Step 2: Fetch Moz metrics
        self.update_state(state='PROGRESS', meta={'progress': 20, 'status': 'Fetching domain metrics'})
        domain = urlparse(url).netloc
        moz_metrics = fetch_moz_metrics(domain)
        
        # Step 3: Process sitemap URLs
        metrics = initialize_metrics_dict()
        sitemap_entries = fetch_sitemap_urls(sitemap_url) or []
        total_urls = len(sitemap_entries)
        
        for i, (sitemap_url, last_modified) in enumerate(sitemap_entries):
            # Check if task was requested to be stopped
            if self.is_aborted():
                return {'status': 'Task aborted', 'progress': 100}
                
            # Update progress
            progress = 30 + (i / total_urls) * 60
            self.update_state(
                state='PROGRESS',
                meta={
                    'progress': progress,
                    'status': f'Analyzing URL {i+1}/{total_urls}'
                }
            )
            
            # Your analysis logic for each URL
            seo_metrics = analyze_page(sitemap_url)
            desktop_metrics = fetch_pagespeed_metrics(sitemap_url, "desktop", api_key)
            mobile_metrics = fetch_pagespeed_metrics(sitemap_url, "mobile", api_key)
            
            # Append metrics
            append_metrics_to_dict(metrics, sitemap_url, last_modified, 
                                 seo_metrics, desktop_metrics, mobile_metrics)
        
        # Step 4: Save results
        self.update_state(state='PROGRESS', meta={'progress': 90, 'status': 'Saving results'})
        excel_file = save_metrics_to_excel(metrics, sitemap_url, moz_metrics)
        grade = calculate_grade(seo_metrics, desktop_metrics, mobile_metrics, moz_metrics)
        
        # Save to database
        with app.app_context():
            analysis = Analysis(
                website_name=domain,
                url=sitemap_url,
                excel_file=excel_file,
                user_id=user_id,
                grade=grade,
                moz_metrics=moz_metrics,
                metrics=metrics
            )
            db.session.add(analysis)
            db.session.commit()
            
            # Update URL usage count
            url_usage = UserUrlUsage.query.filter_by(user_id=user_id).first()
            if url_usage:
                url_usage.urls_used += total_urls
                db.session.commit()
        
        return {
            'status': 'Analysis complete',
            'excel_file': excel_file,
            'grade': grade,
            'domain': domain,
            'analyzed_urls': total_urls
        }
        
    except Exception as e:
        self.retry(exc=e, countdown=60, max_retries=3)
