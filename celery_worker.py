#!/usr/bin/env python
from app import celery, app
from celery.signals import worker_init, worker_shutdown
import logging

# Configure logging
logging.basicConfig(
    format='%(asctime)s %(levelname)s: %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

@worker_init.connect
def init_worker(**kwargs):
    logger.info("Worker initialized")

@worker_shutdown.connect
def shutdown_worker(**kwargs):
    logger.info("Worker shutting down")
    # Clean up resources if needed

if __name__ == '__main__':
    # Start Celery worker with custom options
    celery.worker_main([
        'worker',
        '--loglevel=INFO',
        '--concurrency=4',  # Number of worker processes
        '--without-heartbeat',
        '--without-gossip',
        '--without-mingle'
    ])
