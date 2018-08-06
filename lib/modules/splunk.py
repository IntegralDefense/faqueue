import time, os, sys
import logging
import json
import subprocess
import threading
import csv
import requests
import pprint

from configparser import ConfigParser
from subprocess import Popen
from threading import Lock, Thread

from lib.constants import FA_HOME
from lib.modules import base_module
from lib.splunklib import SplunkQueryObject

log = logging.getLogger()
requests.packages.urllib3.disable_warnings()

class Splunk(base_module.BaseModule):

    def __init__(self):
        super().__init__(name='Splunk')
        log.info('Initializing Splunk module.')
        self.config = ConfigParser()
        self.config.read(os.path.join(FA_HOME, 'etc', 'config.ini'))
        self.working = self.config.get('general', 'working_dir')
        # Determines whether the entire process is running
        self.running = False
        # Dict to track all the crits indicator objects and their status
        self.crits_data = {
            'module_status' : 'initialized',
            'indicators' : {}
            }
        self.data_lock = Lock()
        # Set all our splunk server configs
        self.username = self.config.get('module_splunk', 'username')
        self.password = self.config.get('module_splunk', 'password')
        self.server = self.config.get('module_splunk', 'splunk_server')
        self.port = self.config.get('module_splunk', 'splunk_port')
        self.endpoint = self.config.get('module_splunk', 'splunk_rest_search_endpoint')
        self.splunk_csv = os.path.join(FA_HOME, 'etc', 'splunk_searches.csv')
        self.results_limit = self.config.getint('module_splunk', 'results_limit')
        self.splunk = SplunkQueryObject(uri=self.server, username=self.username, password=self.password)

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
                thread = Thread(target=self.run_splunk_searches, name='SplunkSearch')
                thread.start()

                while thread.is_alive() and self.running:
                    time.sleep(2)
            else:
                time.sleep(2)


    def stop(self):
        log.warning("Caught interrupt. Shutting down Splunk...")
        self.running = False


    def poll(self):
        with self.data_lock:
            return self.crits_data


    def get_valid_indicator_types(self):
        return [
                'Windows - FileName',
                'Windows - FilePath',
                'Windows - Registry',
                'Windows - Service',
                'Windows - Shell',
                'Hash - MD5',
                'Hash - SHA1',
                'Hash - SHA256',
                'URI - URL',
                'URI - Path',
                'URI - Domain Name',
                'URI - HTTP - UserAgent',
                'Email - Subject',
                'Email - Address',
                'Email - Xmailer',
                'Email X-Originating IP',
                'Address - ipv4-addr',
                'Account',
                'IDS - Streetname',
                'Antivirus - Streetname',
                ]


    def run_splunk_searches(self):
        log.info('Running splunk searches.')
        with self.data_lock:
            cid_list = list(self.crits_data['indicators'].keys())
        for cid in cid_list:
            if not self.running:
                return
            # Ignore completed indicators
            with self.data_lock:
                if not cid in self.crits_data['indicators']:
                    log.warning("cid {0} not found in crits_data['indicators']. this shouldn't happen.".format(cid))
                    continue
                if self.crits_data['indicators'][cid]['completed']:
                    continue
            with self.data_lock:
                _searches = self._get_searches_for_type(self.splunk_csv, self.crits_data['indicators'][cid]['type'], self.crits_data['indicators'][cid]['value'])
            _has_hit = False
            _search_failed = False
            for search in _searches:
                if not self.running:
                    return
                results_list = None
                # This is our loop to check for errors in our splunk search
                while results_list is None and self.running:
                    results_list = self._run_search(search)
                    if results_list is None:
                        log.info('Splunk search failed. Sleeping and retrying.')
                        time.sleep(5)
                if len(results_list) > 0:
                    log.info('Splunk hit {} times for indicator {}'.format(len(results_list), cid))
                    with self.data_lock:
                        if 'results' not in self.crits_data['indicators'][cid]:
                            self.crits_data['indicators'][cid]['results'] = []
                        if 'observables' not in self.crits_data['indicators'][cid]:
                            self.crits_data['indicators'][cid]['observables'] = []
                        _results_data = {}
                        _results_data['search'] = search
                        _results_data['hits'] = []
                        _results_data['total_hits'] = len(results_list)
                        current_count = 0
                        for result in results_list:
                            _observables = self._get_observables(result)
                            if current_count > self.results_limit:
                                break
                            current_count += 1
                            _results_data['hits'].append(result)
                            for o in _observables:
                                if o not in self.crits_data['indicators'][cid]['observables']:
                                    self.crits_data['indicators'][cid]['observables'].append(o)
                        self.crits_data['indicators'][cid]['results'].append(_results_data)
                        _has_hit = True
            if _has_hit:
                with self.data_lock:
                    self.crits_data['indicators'][cid]['status'] = 'In Progress'
                    self.crits_data['indicators'][cid]['completed'] = True
            else:
                with self.data_lock:
                    self.crits_data['indicators'][cid]['status'] = 'Analyzed'
                    self.crits_data['indicators'][cid]['completed'] = True


    def _get_observables(self, result):
        _observables = []
        # The keys are a list of fields from splunk results.
        # These are found in the splunk_searches.csv file. We pipe the results and
        # filter on certain types.
        # Map the result type to an observable type ACE can understand
        observable_mapping = {
            'username' : 'user',
            'HostName' : 'hostname',
            'computer_name' : 'hostname',
            'ComputerName' : 'hostname',
            'Account_Name' : 'user',
            'dst_ip' : 'ipv4',
            'src_ip' : 'ipv4',
            'message_id' : 'message_id',
            'url' : 'url',
            'originating_ip' : 'ipv4',
        }

        for obs_type in observable_mapping.keys():
            if obs_type in result.keys():
                if not self._is_valid_observable_value(result[obs_type]):
                    continue
                if obs_type in observable_mapping:
                    obs = { 'type' : observable_mapping[obs_type], 'value' : result[obs_type] }
                    _observables.append(obs)
                else:
                    log.warning('Unknown mapping for observable: {}'.format(obs_type))

        return _observables


    def _is_valid_observable_value(self, value):
        if value == '':
            return False
        if value == '-':
            return False
        if value == None:
            return False
        return True


    def _get_search_string(self, row, indvalue):
        search =  'search ' + row['<Index_Source>'] + ' earliest=-10d'
        indvalue = indvalue.replace('\\', '\\\\')
        indvalue = indvalue.replace('"', '\\"')
        search += ' \"' + indvalue + '\" NOT pcn0351378 NOT pcn0351545'
        search += ' | head 1000 | table ' + row['<Table_Field_List>']
        return search


    def _get_searches_for_type(self, filename, indtype, value):
        csvfile = csv.DictReader(open(filename))
        rows = []
        for each in csvfile:
            if each['<Indicator_Type_Name>'] == indtype:
                rows.append(self._get_search_string(each, value))
        return rows


    def _run_search(self, search_string):
        log.info('Running search: {}'.format(search_string))
        try:
            results = self._search_splunk(search_string)
        except Exception as e:
            log.error('Exception caught while running splunk search: {}'.format(e))
            return None

        return results


    def _search_splunk(self, search_string):
        if self.splunk.authenticate():
            completed = self.splunk.query(search_string)
            if completed:
                if self.splunk.is_job_completed():
                    return self.splunk.json()

        else:
            log.error('Unable to authenticate with splunk.')
            return None

        return None
