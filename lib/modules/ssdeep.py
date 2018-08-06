import json
import os
import logging
import ssdeep
import subprocess
import time

from configparser import ConfigParser
from subprocess import Popen
from threading import Lock, Thread

from lib.constants import FA_HOME
from lib.modules import base_module

log = logging.getLogger()

class SSDeep(base_module.BaseModule):

    def __init__(self):
        super().__init__(name='SSDeep')
        log.info('Initializing SSDeep module.')
        self.config = ConfigParser()
        self.config.read(os.path.join(FA_HOME, "etc", "config.ini"))
        self.running = False
        self.scan_count = self.config.get('module_ssdeep', 'scan_count')
        # 0 - 100
        self.match_threshold = int(self.config.get('module_ssdeep', 'match_threshold'))
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
            unprocessed_cids = []
            for cid in cid_list:
                with self.data_lock:
                    if not self.crits_data['indicators'][cid]['completed']:
                        unprocessed_cids.append(cid)

            # Now we can start a thread to process them
            if len(unprocessed_cids) > 0:
                thread = Thread(target=self.run_ssdeep_scans, name='SSDeepScanner')
                thread.start()

                while thread.is_alive() and self.running:
                    time.sleep(2)
            else:
                time.sleep(2)


    def stop(self):
        log.warning("Caught interrupt. Shutting down ssdeep...")
        self.running = False


    def get_valid_indicator_types(self):
        return [ 'Hash - SSDEEP' ]


    def poll(self):
        with self.data_lock:
            return self.crits_data


    def run_ssdeep_scans(self):
        with self.data_lock:
            cid_list = list(self.crits_data['indicators'].keys())
        for cid in cid_list:
            # Ignore processed indicators
            with self.data_lock:
                if self.crits_data['indicators'][cid]['completed']:
                    continue

            log.info('Running ssdeep scan on indicator {}'.format(cid))
            find_p = Popen(['find', '/mnt/storage', '-maxdepth', '2', '-mindepth', '2', '-type', 'f', '-not', '-name', '"*.*"'], stdout=subprocess.PIPE)
            head_p = Popen(['head', '-n', self.scan_count], stdin=find_p.stdout, stdout=subprocess.PIPE)
            stdout,stderr = head_p.communicate()
            files = stdout.decode('ascii').splitlines()
            failed = False
            for f in files:
                file_hash = ssdeep.hash_from_file(f)
                with self.data_lock:
                    indicator_hash = self.crits_data['indicators'][cid]['value']
                percent_match = ssdeep.compare(file_hash, indicator_hash)
                if percent_match > self.match_threshold:
                    # This indicator fails FAQueue
                    log.info('Indicator {} failed with percentage of {}'.format(cid, percent_match))
                    failed = True
                    # CarbonBlack returns a json report of the file with details
                    report = self._get_json_report(f)
                    if report:
                        with self.data_lock:
                            self.crits_data['indicators'][cid]['results'].append( { 'file_matched' : f, 'score' : percent_match, 'report' : report, 'total_hits' : 1 } )
                        self._attach_json_report_observables(cid, report)
                    else:
                        with self.data_lock:
                            self.crits_data['indicators'][cid]['results'].append( { 'file_matched' : f, 'score' : percent_match, 'total_hits' : 1 } )
            if failed:
                with self.data_lock:
                    self.crits_data['indicators'][cid]['status'] = 'In Progress'
                    self.crits_data['indicators'][cid]['completed'] = True
            else:
                with self.data_lock:
                    self.crits_data['indicators'][cid]['status'] = 'Analyzed'
                    self.crits_data['indicators'][cid]['completed'] = True


    def _get_json_report(self, f):
        json_file = "{}.json".format(f)
        if not os.path.exists(json_file):
            return False
        try:
            with open(json_file, 'r') as fp:
                report = json.loads(fp.read())
            return report
        except Exception as e:
            log.error('Error reading json report: {}'.format(e))
            return False


    # Obtain a list of ACE observables
    # cat /opt/saq/lib/saq/constants.py | grep ^F_
    def _attach_json_report_observables(self, cid, json_report):
        _observables = []
        if 'observed_filename' in json_report:
            for fn in json_report['observed_filename']:
                obs = { 'type' : 'file_path', 'value' : fn }
                _observables.append(obs)
        if 'endpoint' in json_report:
            for ep in json_report['endpoint']:
                try:
                    obs = { 'type' : 'hostname', 'value' : ep.split('|')[0] }
                    _observables.append(obs)
                except Exception as e:
                    log.warning('endpoint object in json report not as expected: {}'.format(ep))
        if 'original_filename' in json_report:
            obs = { 'type' : 'file_name', 'value' : json_report['original_filename'] }
            _observables.append(obs)
        with self.data_lock:
            self.crits_data['indicators'][cid]['observables'] = _observables
#        if 'group' in json_report:
#            for g in json_report['group']:
#                if g == 'VXstream Desktops':
#                    obs = { 'type' 
