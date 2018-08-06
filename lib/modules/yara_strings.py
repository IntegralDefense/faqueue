import time, os, sys
import logging
import json
import subprocess
import threading

from configparser import ConfigParser
from subprocess import Popen
from threading import Lock, Thread

from lib.constants import FA_HOME
from lib.modules import base_module
from lib.mwzoo.core.yara import YaraScanner

log = logging.getLogger()

class YaraStrings(base_module.BaseModule):

    def __init__(self):
        super().__init__(name='YaraStrings')
        log.info('Initializing YaraStrings module.')
        self.config = ConfigParser()
        self.config.read(os.path.join(FA_HOME, "etc", "config.ini"))
        self.working = self.config.get("general", "working_dir")
        self.json_results_file = os.path.join(self.working, 'scan_results.json')
        self.results_limit = self.config.getint('module_yarastrings', 'results_limit')
        self.scan_count = self.config.get('module_yarastrings', 'scan_count')
        # Determines whether the entire yara process is running
        self.running = False
        # Between-method flag to share whether a scan was completed or not and we need to process the results.
        self.scan_completed = False
        self.sleep_time = int(self.config.get('module_yarastrings', 'sleep_time'))
        self.last_run_time = time.time() - self.sleep_time
        self.valid_types = {}
        # Dict to track all the crits indicator objects and their status
        self.crits_data = {
            'module_status' : 'initialized',
            'indicators' : {}
            }
        # Tracks the current group of indicators we are running though yara rules
        self.current_group = []


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
                self.create_yara_rules()
                if self.check_rules():
                    thread = Thread(target=self.run_yara_scans, name='YaraScanner')
                    thread.start()

                    while thread.is_alive() and self.running:
                        time.sleep(2)
            else:
                time.sleep(2)

            # Reset current iteration trackers
            self.valid_types = {}
            self.current_group = []


    def stop(self):
        log.warning("Caught interrupt. Shutting down yara_strings...")
        self.running = False


    def set_crits_data(self, crits_data):
        with self.data_lock:
            self.crits_data = crits_data


    def get_valid_indicator_types(self):
        return [
            'Address - ipv4-addr',
            'Code - Binary_Code',
            'String - Java',
            'String - Office',
            'String - PDF',
            'String - PE',
            'String - RTF',
            'String - SWF',
            #'String - VBS',
            #'String - Windows Shell',
            'URI - Domain Name',
            'URI - Path',
            'URI - URL',
            'Windows - FileName',
            #'Windows - FilePath',
        ]


    def get_valid_scan_type(self, indicator_type):
        all_types = ["dll","doc","docx","exe","jar","pdf","ppt","pptx","rtf","swf","xls","xlsx"]
        type_translation = {
            'Address - ipv4-addr' : all_types,
            'Code - Binary_Code' : [ 'dll', 'exe' ],
            'String - Java' : [ 'jar' ],
            'String - Office' : [ 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx' ],
            'String - PDF' : [ 'pdf' ],
            'String - PE' : [ 'dll', 'exe' ],
            'String - RTF' : [ 'rtf' ],
            'String - SWF' : [ 'swf' ],
            #'String - VBS',
            #'String - Windows Shell',
            'URI - Domain Name' : all_types,
            'URI - Path': all_types,
            'URI - URL' : all_types,
            'Windows - FileName' : all_types,
            #'Windows - FilePath',
        }
        return type_translation[indicator_type]


    def poll(self):
        with self.data_lock:
            return self.crits_data


    def escape_characters(self, yara_string):
        yara_string = str.replace(yara_string, '\\', '\\\\')
        yara_string = str.replace(yara_string, '"', '\\"')
        return yara_string


    def get_rule_basename_from_type(self, name):
        name = str.replace(name, ' ', '')
        name = str.replace(name, '-', '')
        name = str.replace(name, '_', '')
        name = name.lower()
        return 'faqueue_{}_strings'.format(name)


    def create_yara_rules(self):
        for t in self.get_valid_indicator_types():
            # Not the most efficient way to do this probably, but w/e
            # We essentially want to make sure we have an indicator of a specific type
            # before we make a rule for that type
            self.valid_types[t] = False
            with self.data_lock:
                for cid in self.crits_data['indicators'].keys():
                    if self.crits_data['indicators'][cid]['type'] == t:
                        if not self.crits_data['indicators'][cid]['completed']:
                            self.valid_types[t] = True
                            break

            # Now create the rule
            if self.valid_types[t]:
                log.debug('Creating rule for type {}'.format(t))
                rulename = self.get_rule_basename_from_type(t)
                fout = open(os.path.join(self.working, '{}.yar'.format(rulename)), 'w')
                fout.write('rule ' + rulename + ' {\n')
                fout.write('  strings:\n')
                count = 0
                with self.data_lock:
                    for cid in self.crits_data['indicators'].keys():
                        if self.crits_data['indicators'][cid]['type'] == t:
                            if not self.crits_data['indicators'][cid]['completed']:
                                # Track this indicator in our current iteration group
                                self.current_group.append(cid)
                                count += 1
                                value = self.escape_characters(self.crits_data['indicators'][cid]['value'])
                                # Write the yara rule
                                fout.write('    $crits_{} = "{}" ascii wide nocase\n'.format(cid, value))
                fout.write('  condition:\n')
                fout.write('    any of them\n')
                fout.write('}\n')
                fout.close()
                log.info('Yara rule created for type {} with {} strings.'.format(t, count))


    def check_rules(self):
        _all_valid = True
        for t in self.get_valid_indicator_types():
            if self.valid_types[t]:
                rulename = self.get_rule_basename_from_type(t)
                rule_path = os.path.join(self.working, '{}.yar'.format(rulename))
                yara_scanner = YaraScanner(rules_file=rule_path)
                if not yara_scanner.test_rules():
                    _all_valid = False
        return _all_valid


    def parse_results(self, crits_type, results={}):
        if not 'results' in results:
            log.error('Wrong format in results. Expected "results" key.')
            # TODO: Figure out what to do here
            return
        for result in results['results']:
            # We need to tally up the unique binaries for each cid.
            # Because of the way the yara results are returned, we have to do it
            # in a not-quite-efficient way
            _unique_hits = {}
            for obj in result:
                #log.debug('File {} hit on {} strings'.format(obj['target'], len(obj['strings'])))
                for string_list in obj['strings']:
                    # First we have to parse out the crits id from the string. It is in this format:
                    # $crits_567996abbcb87fa89d983820
                    cid = string_list[1]
                    cid = str.split(cid, '_')[1]
                    # Now we set it to in progress since it hit on a file and needs to be reviewed
                    with self.data_lock:
                        if cid in self.crits_data['indicators'].keys():
                            if self.crits_data['indicators'][cid]['status'] == 'New':
                                self.crits_data['indicators'][cid]['status'] = 'In Progress'
                                self.crits_data['indicators'][cid]['completed'] = True
                                self.crits_data['indicators'][cid]['processing_results'] = True
                                log.debug('id {} set to In Progress'.format(cid))
                            # Now gather results data to send to ACE
                            if 'results' not in self.crits_data['indicators'][cid]:
                                self.crits_data['indicators'][cid]['results'] = []
                            if len(self.crits_data['indicators'][cid]['results']) == 0:
                                self.crits_data['indicators'][cid]['results'] = [{ 'total_hits' : 0, 'unique_binary_hits' : 0, 'total_binaries' : self.scan_count, 'matched' : [] }]
                            # Tally unique hits
                            if cid not in _unique_hits:
                                _unique_hits[cid] = {}
                            _target_md5 = os.path.basename(obj['target'])
                            _unique_hits[cid][_target_md5] = obj['target']
                            with open('/tmp/critsdata', 'w') as fp:
                                json.dump(self.crits_data, fp)
                            self.crits_data['indicators'][cid]['results'][0]['total_hits'] += 1
                            # Ensure we aren't over our limit
                            if len(self.crits_data['indicators'][cid]['results'][0]['matched']) < self.results_limit:
                                _match = {}
                                _match['target'] = obj['target']
                                _match['strings'] = string_list[2]
                                self.crits_data['indicators'][cid]['results'][0]['matched'].append(_match)

                        else:
                            log.error('id {} not found in self.crits_data!'.format(cid))
            # Now we can go back through and add the unique_binary_hits count into the data
            with self.data_lock:
                for cid in _unique_hits.keys():
                    hit_count = len(_unique_hits[cid].keys())
                    self.crits_data['indicators'][cid]['results'][0]['unique_binary_hits'] = hit_count

        status_counts = { 'New' : 0, 'In Progress' : 0, 'Analyzed' : 0 }
        with self.data_lock:
            for cid in self.current_group:
                if cid not in self.crits_data['indicators']:
                    log.warning('crits id {} not found in self.crits_data[indicators]'.format(cid))
                    continue
                # Parsing one type at a time due to splitting rules out by type
                if self.crits_data['indicators'][cid]['status'] == 'New' and self.crits_data['indicators'][cid]['type'] == crits_type:
                    self.crits_data['indicators'][cid]['status'] = 'Analyzed'
                    self.crits_data['indicators'][cid]['completed'] = True
                    self.crits_data['indicators'][cid]['processing_results'] = False

                # We are finished processing the indicator
                if self.crits_data['indicators'][cid]['status'] != 'New' and self.crits_data['indicators'][cid]['type'] == crits_type:
                    self.crits_data['indicators'][cid]['processing_results'] = False

                log.debug('id {} with status {}'.format(cid, self.crits_data['indicators'][cid]['status']))
                status_counts[self.crits_data['indicators'][cid]['status']] += 1

        log.info('=== Status Totals ===')
        log.info('New         : {}'.format(status_counts['New']))
        log.info('In Progress : {}'.format(status_counts['In Progress']))
        log.info('Analyzed    : {}'.format(status_counts['Analyzed']))


    def run_yara_scans(self):
        for t in self.get_valid_indicator_types():
            if t not in self.valid_types:
                log.warning('{} was not found in self.valid_types'.format(t))
                continue
            if self.valid_types[t]:
                log.debug('Running yara scan for type {}'.format(t))
                rulename = self.get_rule_basename_from_type(t)
                rule_path = os.path.join(self.working, '{}.yar'.format(rulename))
                log.info('Running yara scan on {}.yar.'.format(rulename))
                self.scan_completed = False
                self.last_scan_time = time.time()
                # Loop and gather and scan all the things
                scan_these = []
                for scan_dir in self.get_valid_scan_type(t):
                    find_p = Popen(['find', '/opt/files/benign/vt/{}/'.format(scan_dir), '-maxdepth', '1', '-mindepth', '1', '-type', 'f'], stdout=subprocess.PIPE)
                    head_p = Popen(['head', '-n', self.scan_count], stdin=find_p.stdout, stdout=subprocess.PIPE)
                    stdout, stderr = head_p.communicate()
                    for f in stdout.decode('ascii').splitlines():
                        scan_these.append(f)

                # Run our yara_scanner
                yara_scanner = YaraScanner(rules_file=rule_path)
                log.info('Running yara scan on {} files with rule '
                         '{}'.format(len(scan_these), rulename))
                results = yara_scanner.run_scans(sample_paths=scan_these)
                with open('/tmp/yara_results.tmp', mode='w', encoding='utf-8') as fp:
                    json.dump(results, fp)

                if self.running:
                    log.info('Scan complete for type {}. Parsing results.'.format(t))
                    self.parse_results(t, results)
                log.debug('FINISHED running type {}'.format(t))
