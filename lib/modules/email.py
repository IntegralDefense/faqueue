import glob
import json
import logging
import os
import subprocess
import threading
import time
import yara

from configparser import ConfigParser
from threading import Lock, Thread

from lib.constants import FA_HOME
from lib.modules import base_module

log = logging.getLogger()

class Email(base_module.BaseModule):

    def __init__(self):
        super().__init__(name='Email')
        log.info('Initializing Email module.')
        self.config = ConfigParser()
        self.config.read(os.path.join(FA_HOME, "etc", "config.ini"))
        self.working = os.path.join(self.config.get("general", "working_dir"), 'email')
        self.raw_email_dir = os.path.join(self.config.get("general", "working_dir"), 'email', 'raw')
        self.archive_email_dir = self.config.get("module_email", "email_dir")
        self.scan_count = self.config.get("module_email", "email_count")
        self.gpg_passphrase = self.config.get("module_email", "gpg_passphrase")
        self.json_results_file = os.path.join(self.working, 'email_scan_results.json')
        self.results_limit = 10
        self.running = False
        # Between-method flag to share whether a scan was completed or not and we need to process the results.
        self.scan_completed = False
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
        if not os.path.exists(self.working):
            os.makedirs(self.working)
        if not os.path.exists(self.raw_email_dir):
            os.makedirs(self.raw_email_dir)
        with self.data_lock:
            self.crits_data['module_status'] = 'running'
        self.delete_email_data()
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
                self.copy_email_data()
                if self.check_rules():
                    log.debug('Starting email yara scan thread.')
                    thread = Thread(target=self.run_yara_scans, name='EmailScanner')
                    thread.start()

                    while thread.is_alive() and self.running:
                        time.sleep(2)
                else:
                    log.warning('Rule check failed.')
                # Since we are finished, delete the emails
                #self.delete_email_data()
            else:
                time.sleep(2)

            # Reset current iteration trackers
            self.valid_types = {}
            self.current_group = []


    def stop(self):
        log.warning("Caught interrupt. Shutting down email yara...")
        self.running = False


    def set_crits_data(self, crits_data):
        with self.data_lock:
            self.crits_data = crits_data


    def get_valid_indicator_types(self):
        return [ 'Email - Content', 'Email Header Field' ]


    def poll(self):
        with self.data_lock:
            return self.crits_data


    def escape_characters(self, yara_string):
        yara_string = str.replace(yara_string, '\\', '\\\\')
        yara_string = str.replace(yara_string, '"', '\\"')
        yara_string = str.replace(yara_string, '\x0d\x0a', '\\x0d\\x0a')
        return yara_string


    def get_rule_basename_from_type(self, typestr):
        name = typestr[8:]
        name = str.replace(name, ' ', '_')
        name = name.lower()
        return 'faqueue_{}_email'.format(name)


    def copy_email_data(self):
        # Copy emails from our archive into the directory at self.raw_email_dir
        log.debug('Copying and decrypting email files.')
        find_p = subprocess.Popen(['find', self.archive_email_dir, '-type', 'f'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        head_p = subprocess.Popen(['head', '-n', self.scan_count], stdin=find_p.stdout, stdout=subprocess.PIPE)

        results = head_p.communicate()
        file_list = results[0].decode('ascii')
        file_list = file_list.rstrip()
        file_list = file_list.split('\n')
        log.debug('Email list size: {}'.format(len(file_list)))

        for f in file_list:
            if not self.running:
                break
            # Cut off the .gpg on the end of the filename
            outpath = os.path.join(self.raw_email_dir, os.path.basename(f)[:-4])
            gpg_p = subprocess.Popen(['gpg', '--decrypt', '--no-tty', '--passphrase', self.gpg_passphrase, f], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            results = gpg_p.communicate()
            stdout = results[0]
            stderr = results[1]
            # gpg decrypts to stdout
            # write it to a file
            with open(outpath, 'wb') as fp:
                fp.write(results[0])
            if stdout == '' and stderr == '':
                log.warning('No data received from p.communicate()')
            gzip_p = subprocess.Popen(['gzip', '-d', outpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                gz_results = gzip_p.communicate(timeout=5)
                gz_stdout = gz_results[0]
                gz_stderr = gz_results[1]
            except subprocess.TimeoutExpired as e:
                log.warning('Gzip extraction timed out for {}'.format(outpath))
                continue


    def delete_email_data(self):
        log.debug('Removing old emails')
        rm_dir = os.path.join(self.raw_email_dir, '*')
        for f in glob.glob(rm_dir):
            os.remove(f)


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
                rulepath = os.path.join(self.working, '{}.yar'.format(rulename))

                try:
                    compiled_yara = yara.compile(rulepath)
                except Exception as e:
                    log.warning('Yara rule failed compilation: {}'.format(rulepath))
                    _all_valid = False
        return _all_valid


    def parse_results(self, results, crits_type):
        # We need to tally up the unique binaries for each cid.
        # Because of the way the yara results are returned, we have to do it
        # in a not-quite-efficient way
        _unique_hits = {}
        for email_file in results.keys():
            #log.debug('File {} hit on {} strings'.format(obj['target'], len(obj['strings'])))
            for (line, cid, match) in results[email_file]:
                # First we have to parse out the crits id from the string. It is in this format:
                # $crits_567996abbcb87fa89d983820
                cid = str.split(cid, '_')[1]
                # Now we set it to in progress since it hit on a file and needs to be reviewed
                with self.data_lock:
                    if cid in self.crits_data['indicators'].keys():
                        if self.crits_data['indicators'][cid]['status'] == 'New':
                            self.crits_data['indicators'][cid]['status'] = 'In Progress'
                            self.crits_data['indicators'][cid]['completed'] = True
                            log.debug('id {} set to In Progress'.format(cid))
                        # Now gather results data to send to ACE
                        if 'results' not in self.crits_data['indicators'][cid]:
                            self.crits_data['indicators'][cid]['results'] = [{ 'total_hits' : 0, 'unique_email_hits' : 0, 'total_emails' : self.scan_count, 'matched' : [] }]
                        if len(self.crits_data['indicators'][cid]['results']) == 0:
                            self.crits_data['indicators'][cid]['results'] = [{ 'total_hits' : 0, 'unique_email_hits' : 0, 'total_emails' : self.scan_count, 'matched' : [] }]
                        # Tally unique hits
                        if cid not in _unique_hits:
                            _unique_hits[cid] = {}
                        _unique_hits[cid][email_file] = 1
                        self.crits_data['indicators'][cid]['results'][0]['total_hits'] += 1
                        # Ensure we aren't over our limit
                        if len(self.crits_data['indicators'][cid]['results'][0]['matched']) < self.results_limit:
                            _match = {}
                            _match['target'] = email_file
                            _match['strings'] = match
                            self.crits_data['indicators'][cid]['results'][0]['matched'].append(_match)

                    else:
                        log.error('id {} not found in self.crits_data!'.format(cid))
            # Now we can go back through and add the unique_email_hits count into the data
            with self.data_lock:
                for cid in _unique_hits.keys():
                    hit_count = len(_unique_hits[cid].keys())
                    self.crits_data['indicators'][cid]['results'][0]['unique_email_hits'] = hit_count

        status_counts = { 'New' : 0, 'In Progress' : 0, 'Analyzed' : 0 }
        with self.data_lock:
            for cid in self.current_group:
                # Parsing one type at a time due to splitting rules out by type
                if self.crits_data['indicators'][cid]['status'] == 'New' and self.crits_data['indicators'][cid]['type'] == crits_type:
                    self.crits_data['indicators'][cid]['status'] = 'Analyzed'
                    self.crits_data['indicators'][cid]['completed'] = True
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
                log.info('Running yara scan on {}.yar.'.format(rulename))
                self.scan_completed = False
                self.last_scan_time = time.time()
                # Run our yara scan on the emails
                results = {}
                rule_path = os.path.join(self.working, '{}.yar'.format(rulename))
                log.debug('Compiling file: {}'.format(rule_path))
                compiled = yara.compile(rule_path)
                for email_file in os.listdir(self.raw_email_dir):
                    results[email_file] = []
                    matches = compiled.match(os.path.join(self.raw_email_dir, email_file))
                    for m in matches:
                        for s in m.strings:
                            results[email_file].append(s)

                if self.running:
                    log.info('Scan complete for type {}. Parsing results.'.format(t))
                    self.parse_results(results, t)
