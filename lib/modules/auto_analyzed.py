import logging
import os
import time

from configparser import ConfigParser
from threading import Lock

from lib.constants import FA_HOME
from lib.modules import base_module

log = logging.getLogger()

class AutoAnalyzed(base_module.BaseModule):

    def __init__(self):
        super().__init__(name='AutoAnalyzed')
        log.info('Initializing SSDeep module.')
        self.config = ConfigParser()
        self.config.read(os.path.join(FA_HOME, "etc", "config.ini"))
        self.running = False
        self.crits_data = {
            'module_status' : 'initialized',
            'indicators' : {}
            }


    def run(self):
        self.running = True
        with self.data_lock:
            self.crits_data['module_status'] = 'running'
        while self.running:
            # We need to find indicators that haven't been processed already
            with self.data_lock:
                cid_list = list(self.crits_data['indicators'].keys())
            for cid in cid_list:
                with self.data_lock:
                    if not self.crits_data['indicators'][cid]['completed']:
                        self.crits_data['indicators'][cid]['status'] = 'Analyzed'
                        self.crits_data['indicators'][cid]['completed'] = True

            time.sleep(2)


    def stop(self):
        log.warning("Caught interrupt. Shutting down auto_analyzed...")
        self.running = False


    def get_valid_indicator_types(self):
        return ['String - VBS', 'String - EPS', 'String - Unix Shell', 'Email Message ID', 'Windows - Mutex']


    def poll(self):
        with self.data_lock:
            return self.crits_data
