#!/usr/bin/env python3
import os, sys
import signal
import logging
import logging.config
import string
import argparse

from configparser import ConfigParser
from lib.constants import FA_HOME
from lib.scheduler import Scheduler

log = logging.getLogger()

class FAQueue:
    def __init__(self):
        # Load our config first
        config = ConfigParser()
        config.read(os.path.join(FA_HOME, "etc", "config.ini"))

        # Create the logging directory if it does not exist
        logging_dir = config.get("general", "logging_dir")
        if not os.path.exists(logging_dir):
            print('Creating log directory: {}'.format(logging_dir))
            os.makedirs(logging_dir)

        # Initialize logging
        log_path = os.path.join(FA_HOME, 'etc', 'logging.ini')
        try:
            logging.config.fileConfig(log_path)
        except Exception as e:
            sys.exit('unable to load logging configuration file {}: {}'.format(log_path, str(e)))

        # Quick hack
        logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.WARNING)

        # Set our environment proxy variables
        os.environ['http_proxy'] = config.get('proxy', 'http_proxy')
        os.environ['https_proxy'] = config.get('proxy', 'https_proxy')
        log.info('Using http_proxy {}'.format(os.environ['http_proxy']))
        log.info('Using https_proxy {}'.format(os.environ['https_proxy']))

        # Create directories if they do not exist
        working_dir = config.get("general", "working_dir")
        if not os.path.exists(working_dir):
            log.info("Working directory does not exist. Creating...")
            os.makedirs(working_dir)

        self.scheduler = None
        # Register the signal handler for SIGINT.
        signal.signal(signal.SIGINT, self.signal_handler)

    def run(self):
        self.scheduler = Scheduler()
        self.scheduler.start()


    def signal_handler(self, signum, frame):
        """ Signal handler so the process pool can complete gracefully. """
        log.warning('Caught signal to terminate! Waiting for pool to finish processing.')
        if self.scheduler:
            self.scheduler.stop()
            log.warning('Goodbye.')
        else:
            log.warning('Scheduler not running. Goodbye.')
        sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='You are running FA queue version {}'.format('0.1'))
    args = parser.parse_args()

    faqueue = FAQueue()
    faqueue.run()
