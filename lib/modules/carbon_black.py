import time, os, sys
import logging
import threading
import datetime
import pprint
import copy

from configparser import ConfigParser
from threading import Lock, Thread

from lib.constants import FA_HOME
from lib.modules import base_module
import lib.cbapi_3 as cbapi_3

log = logging.getLogger()

class CarbonBlack(base_module.BaseModule):

    def __init__(self):
        super().__init__(name='CarbonBlack')
        log.info('Initializing CarbonBlack module.')
        self.config = ConfigParser()
        self.config.read(os.path.join(FA_HOME, "etc", "config.ini"))
        self.working = self.config.get("general", "working_dir")
        self.running = False
        # Dict to track all the crits indicator objects and their status
        self.crits_data = {
            'module_status' : 'initialized',
            'indicators' : {}
            }
        self.data_lock = Lock()
        # CB specific things
        self.cb_url = self.config.get('module_carbonblack', 'url')
        self.cb_token = self.config.get('module_carbonblack', 'token')
        self.cb_time_range = self.config.getint('module_carbonblack', 'time_range')
        self.results_limit = self.config.getint('module_carbonblack', 'results_limit')


    def run(self):
        self.running = True
        with self.data_lock:
            self.crits_data['module_status'] = 'running'
        while self.running:
            # We need to find indicators that haven't been processed already
            cid_list = list(self.crits_data['indicators'].keys())
            unprocessed_cids = []
            for cid in cid_list:
                with self.data_lock:
                    if not self.crits_data['indicators'][cid]['completed']:
                        unprocessed_cids.append(cid)

            # Now we can start a thread to process them
            if len(unprocessed_cids) > 0:
                thread = Thread(target=self.run_cb_scan, name='CarbonBlackScanner')
                thread.start()

                while thread.is_alive() and self.running:
                    time.sleep(2)
            else:
                time.sleep(2)


    def stop(self):
        log.warning("Caught interrupt. Shutting down carbon_black...")
        self.running = False


    def get_valid_indicator_types(self):
        return [
            'Windows - FileName',
            'Hash - MD5',
            'Address - ipv4-addr',
            'URI - Domain Name',
            'Windows - FilePath',
            'Windows - Registry',
            'Account',
            'String - Windows Shell',
        ]


    def run_cb_scan(self):
        # Create a copy of the crits_data so we don't lock it up for a long time while we
        # wait for the carbon black scans to complete.
        with self.data_lock:
            cid_list = list(self.crits_data['indicators'].keys())
        for cid in cid_list:
            if not self.running:
                # Bail out!
                return

            # Ignore completed indicators
            with self.data_lock:
                if self.crits_data['indicators'][cid]['completed']:
                    continue

            with self.data_lock:
                new_value = self._sanitize_string(self.crits_data['indicators'][cid]['value'], self.crits_data['indicators'][cid]['type'])

            time_search = 'server_added_timestamp:[{0} TO *]'.format((datetime.datetime.utcnow() - datetime.timedelta(days=self.cb_time_range)).strftime('%Y-%m-%dT%H:%M:%S'))

            cb = cbapi_3.CbApi(self.cb_url, token=self.cb_token, ssl_verify=False)
            try:
                search = "{} {}".format(new_value, time_search)
                procs = cb.process_search(search)
                log.info("CarbonBlack search: {} returned {} results.".format(search, procs['total_results']))
                if procs['total_results'] == 0:
                    with self.data_lock:
                        self.crits_data['indicators'][cid]['status'] = 'Analyzed'
                        self.crits_data['indicators'][cid]['completed'] = True
                elif procs['total_results'] > 0:
                    with self.data_lock:
                        # We have hits, so set to 'In Progress'
                        self.crits_data['indicators'][cid]['status'] = 'In Progress'
                        # Now gather results data to send to ACE
                        if 'results' not in self.crits_data['indicators'][cid]:
                            self.crits_data['indicators'][cid]['results'] = []
                        _results_data = {}
                        _results_data['search'] = search
                        _results_data['hits'] = []
                        _results_data['total_hits'] = procs['total_results']
                        current_count = 0
                        for result in procs['results']:
                            if current_count > self.results_limit:
                                break
                            current_count += 1
                            _results_data['hits'].append(result)
                        self.crits_data['indicators'][cid]['results'].append(_results_data)
                        self.crits_data['indicators'][cid]['completed'] = True

                else:
                    log.error('Received total_results less than 0. WTF?')
            except Exception as e:
                log.error("{} FAILED. {}".format(new_value, str(e)))
                log.error("Indicator ID was: {}".format(cid))
                log.info("Enabling indicator {}".format(cid))
                with self.data_lock:
                    self.crits_data['indicators'][cid]['status'] = 'Analyzed'
                    self.crits_data['indicators'][cid]['completed'] = True

        log.info('CarbonBlack searches complete.')


    def _sanitize_string(self, value, ind_type):
        if ind_type == 'Hash - MD5':
            value = 'md5:' + value
            return value
        if ind_type == 'Address - ipv4-addr':
            value = 'ipaddr:' + value
            return value
        if ind_type == 'URI - Domain Name':
            value = 'domain:' + value
            return value
        if '"' in value:
            value = value.replace('"', '\\"')
        if '(' in value:
            value = value.replace('(', '\\(')
        if ')' in value:
            value = value.replace(')', '\\)')
        value = '"' + value + '"'
        #if '(' in value:
        #    value = value.replace('\\(')

        return value
