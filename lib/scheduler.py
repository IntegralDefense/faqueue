import time, os, sys
import logging
import json
import importlib
import threading
import pprint
import datetime
import gc
import re
import shutil

from configparser import ConfigParser
from pymongo import MongoClient
from bson.objectid import ObjectId
from subprocess import Popen
from threading import Lock, Thread

from lib.constants import FA_HOME
from lib.saq.client import Alert, AlertSubmitException

log = logging.getLogger()

class Scheduler:
    def __init__(self):
        log.info('Initializing scheduler.')
        self.config = ConfigParser()
        self.config.read(os.path.join(FA_HOME, 'etc', 'config.ini'))
        self.working = self.config.get('general', 'working_dir')
        self.logging_dir = self.config.get('general', 'logging_dir')
        self.json_results_file = os.path.join(self.working, 'scan_results.json')
        self.running = True
        self.update_minutes = self.config.getint('general', 'update_minutes')
        # Thread to regularly update the master list of indicators and their final status
        self.update_list_thread = None
        self.master_indicator_dict = {}
        self.master_indicator_lock = Lock()
        self.has_initial_data = False
        # Module data structures
        self.modules = []
        self.module_classes = {}
        # Informational tracking
        # Tracks types that don't have a module
        self.orphaned_types = []

        # Now we can initialize all our modules
        modules_to_load = self.config.get('general', 'load_modules').split(',')
        for m in modules_to_load:
            mcfg = 'module_{}'.format(m)
            if mcfg in self.config:
                log.info('Loading module {}'.format(m))
                try:
                    _class_name = self.config.get(mcfg, 'class_name')
                    _module_name = 'lib.modules.{}'.format(self.config.get(mcfg, 'module_name'))
                    log.debug('Loading module: {}'.format(_module_name))
                    _module = importlib.import_module(_module_name)
                    log.debug('Loading class: {}'.format(_class_name))
                    _class = getattr(_module, _class_name)
                    self.module_classes[_class_name] = _class
                    log.debug('Creating instance of module: {}'.format(_class_name))
                    _module_instance = _class()
                    self.modules.append(_module_instance)
                except ImportError as e:
                    log.error('Error importing module. {}'.format(e))
                except AttributeError as e:
                    log.error('Error importing class. {}'.format(e))
            else:
                log.error('Module {} configuration not found!'.format(m))


    def start(self):
        # Start a new thread to hold a master list of all 'New' indicators and update it regularly
        # This updates the indicator list as new indicators are found in CRITS
        self.update_list_thread = Thread(target = self.update_master_indicator_list, name='IndicatorMaster')
        self.update_list_thread.start()

        # Wait until our master_indicator_dict contains our first set of indicators
        # A little hacky, but whatever
        log.info('Obtaining initial indicator data.')
        while not self.has_initial_data:
            time.sleep(1)
        log.info('Initial data obtained. Starting modules.')

        # Get our indicator data and start the modules
        for module in self.modules:
            self.start_module(module)

        # Finally, make sure our modules aren't broken
        for module in self.modules:
            status = module.get_module_status()
            if not status:
                log.error('module_status field not found in module data for {}. Shutting down...'.format(module.getName()))
                self.running = False
                break
            if status == 'not initialized':
                log.error('Module {} not initialized! Cannot update indicators!'.format(module.getName()))
                self.running = False
                break

        # Start the main loop
        sleeptime = 10
        while self.running:
            try:
                with self.master_indicator_lock:
                    all_cids = list(self.master_indicator_dict.keys())

                # looping through all crits ids
                for cid in all_cids:
                    with self.master_indicator_lock:
                        status = self.master_indicator_dict[cid]['status']
                        ctype = self.master_indicator_dict[cid]['type']
                        value = self.master_indicator_dict[cid]['value']

                    # Process indicators by their status
                    # This may or may not update the overall status depending on whether
                    # all the modules have finished for that particular indicator
                    if status == 'New':
                        self._process_new_indicator(cid, ctype, value)
                        self._process_indicator_status(cid, ctype)

                    # If the status is something other than 'New', we update the indicator and remove it from
                    # all of the modules.
                    if status == 'In Progress' or status == 'Analyzed':
                        # Update the CRITS status
                        self.update_indicator_status(cid, status)

                        # Send alerts to CRITS
                        if status == 'In Progress':
                            self.send_alert_to_ace(cid)

                        with self.master_indicator_lock:
                            self.master_indicator_dict[cid]['submitted'] = True

                # Remove the indicator from our master_indicator_dict
                self.clean_master_and_modules()

                collected = gc.collect()
                if collected > 0:
                    log.debug('Garbage Collector: Collected {} objects.'.format(collected))

                scount = 0
                while scount < sleeptime and self.running:
                    time.sleep(1)
                    scount += 1

            except KeyboardInterrupt:
                log.info('Keyboard interrupt caught in scheduler. Terminating...')
                self.stop()


    def _process_new_indicator(self, cid, ctype, value):
        # First we will see if we need to add the indicator to the modules
        has_module = False
        for module in self.modules:
            if ctype not in module.get_valid_indicator_types():
                continue
            if module.has_indicator(cid):
                has_module = True
                continue
            log.info('Adding new indicator to all the modules: {}'.format(value))
            has_module = True
            module.add_indicator(cid, value, ctype)

        # Reporting that an indicator type does not have a module
        # This means we need to write a module
        if not has_module:
            if ctype not in self.orphaned_types:
                self.orphaned_types.append(ctype)
                log.warning('No module for indicator type {} and indicator {}'.format(ctype, cid))


    def _process_indicator_status(self, cid, ctype):
        # Now we will check the status of the indicators and see if we can update the overall
        # status from 'New' to either 'In Progress' or 'Analyzed'
        # Can we update this module
        _can_update = True
        # If only one module says "in progress", we set this to False
        _is_in_progress = False
        # We want to make sure at least one module can analyze an indicator before we set it to 'Analyzed'.
        # Otherwise it stays 'New'. This flag tracks that.
        _at_least_one_analyzed = False
        for module in self.modules:
            # Now we process the results data
            module_data = module.get_indicator_data(cid)
            if not module_data and ctype in module.get_valid_indicator_types():
                log.warning('Module {} can handle indicator type '\
                    '{} for {}, but it is not in the module data.'.format(module.getName(), ctype, cid))
                _can_update = False
                continue
            if not module_data:
                continue
            if module_data['status'] == 'New':
                _can_update = False
            if module_data['processing_results']:
                # We are still processing results
                _can_update = False
            # One module says it is 'in progress', so that's what we mark it
            if module_data['status'] == 'In Progress':
                _is_in_progress = True
                _is_analyzed = False
            if module_data['status'] == 'Analyzed':
                _at_least_one_analyzed = True
        # Now we check the results!
        # We set the ultimate result in master_indicator_dict, which is what the mongo update function will use
        if _can_update:
            if _is_in_progress:
                log.debug('Setting indicator {} to "In Progress"'.format(cid))
                with self.master_indicator_lock:
                    self.master_indicator_dict[cid]['status'] = 'In Progress'
            elif _at_least_one_analyzed:
                log.debug('Setting indicator {} to "Analyzed"'.format(cid))
                with self.master_indicator_lock:
                    self.master_indicator_dict[cid]['status'] = 'Analyzed'
        else:
            log.debug('Not updating indicator {}'.format(cid))


    def start_module(self, module):
        module.start()


    def stop(self):
        self.running = False
        for module in self.modules:
            module.stop()


    def get_all_new_indicators(self):
        mongo_host = self.config.get('database', 'host')
        mongo_port = int(self.config.get('database', 'port'))
        try:
            connection = MongoClient(host=mongo_host, port=mongo_port)
            db = connection['crits']
            whitelist_reg = re.compile('^whitelist:')
            collection = db.indicators.find( { 'status' : 'New',
                                              'confidence.rating' : { '$ne' :
                                                                     'benign' },
                                              'impact.rating' : { '$ne' :
                                                                 'benign' },
                                              'bucket_list' : { '$nin' : [
                                                  whitelist_reg ] }
                                             } )
            return list(collection)
        except Exception as e:
            sys.exit('Error retrieving data from mongo: {}'.format(str(e)))
        finally:
            connection.close()


    def update_indicator_status(self, cid, status):
        mongo_host = self.config.get('database', 'host')
        mongo_port = int(self.config.get('database', 'port'))
        try:
            connection = MongoClient(host=mongo_host, port=mongo_port)
            db = connection['crits']
            # Make sure the indicator is still New first
            log.debug('Ensuring indicator {} is still New'.format(cid))
            indicator = db.indicators.find_one( { '_id' : ObjectId(cid) } )
            if indicator['status'] != 'New':
                log.warning('Tried to update indicator {} but status was not New. Status was {}'.format(cid, indicator['status']))
                return False
            # Now we can update the indicator
            log.info('Updating indicator {} with status {}'.format(cid, status))
            db.indicators.update_one( { '_id' : ObjectId(cid)}, { '$set' : { 'status' : status } } )
            return True
        except Exception as e:
            log.error('Error retrieving data from mongo: {}'.format(e))
        finally:
            connection.close()
        return False


    def send_alert_to_ace(self, cid):
        # Create the basic alert data
        with self.master_indicator_lock:
            ind_value = self.master_indicator_dict[cid]['value']
        _results = { 'indicator' : { 'crits_id' : cid, 'value' : ind_value } }
        _observables = []
        _observables.append( { 'type' : 'indicator', 'value' : cid } )
        total_hit_count = 0

        _at_least_one_module = False
        for module in self.modules:
            if module.has_indicator(cid):
                _at_least_one_module = True
                module_results = module.get_indicator_data(cid)
                _results[module.getName()] = module_results['results']
                for fa_result in module_results['results']:
                    total_hit_count += int(fa_result['total_hits'])
                    if 'observables' in module_results:
                        obs_count = 0
                        for observable in module_results['observables']:
                            obs_count += 1
                            _observables.append( observable )
                            log.debug('Adding observable {} {}'.format(observable['type'], observable['value']))

        if not _at_least_one_module:
            log.warning('Tried to submit an alert to ACE, but no module has this indicator: {}'.format(cid))
            return False

        # Send results
        log.info('Sending alert to ACE for indicator {}'.format(cid))
        alert = Alert(
            tool = 'faqueue',
            tool_instance = 'nakylexsec101',
            alert_type = 'faqueue',
            desc = 'FA Queue - Indicator {} - {} Hits'.format(ind_value, total_hit_count),
            event_time = datetime.datetime.now(),
            details = _results
            )
        for obs in _observables:
            alert.add_observable(obs['type'], obs['value'])

        try:
            alert.submit(self.config.get('general', 'ace_submit'), 'blah')
        except Exception as e:
            log.error('Error submitting alert to ACE: {}'.format(str(e)))

        # This means we can remove the indicator from all the modules and our master list
        self.master_indicator_dict[cid]['submitted'] = True

        # Check for alerts that failed submission and attempt to resubmit them
        failed_alerts_path = os.path.join(FA_HOME, '.saq_alerts')
        if os.path.exists(failed_alerts_path):
            for alert_dir in os.listdir(failed_alerts_path):
                if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', alert_dir):
                    continue
                data_file = os.path.join(failed_alerts_path, alert_dir, 'data.json')
                alert_full_path = os.path.join(failed_alerts_path, alert_dir)
                alert = Alert()
                url = None
                key = None

                ok_to_delete = False
                try:
                    url, key = alert.load_saved_alert(data_file)
                    alert.submit(url, key, save_on_fail=False)
                    ok_to_delete = True
                except AlertSubmitException as e:
                    log.error("Failed to re-submit alert to ACE with the following error: {}".format(str(e)))
                except Exception as e:
                    log.error("Unable to load alert from {0}: {1}".format(data_file, str(e)))
                    ok_to_delete = True

                if ok_to_delete:
                    try:
                        shutil.rmtree(alert_full_path)
                    except Exception as e:
                        log.error("Unable to delete directory {0}: {1}".format(alert_full_path, str(e)))


    def update_master_indicator_list(self):
        # Update every X minutes
        update_time = self.update_minutes * 60
        last_update_time = time.time() - update_time - 1
        while self.running:
            current_time = time.time()
            if current_time - last_update_time > update_time:
                # log.debug('Updating the master indicator list.')
                indicators = self.get_all_new_indicators()
                new_indicator_count = 0
                total_indicator_count = 0
                with self.master_indicator_lock:
                    for indicator in indicators:
                        cid = str(indicator['_id'])
                        ctype = indicator['type']
                        cvalue = indicator['value']
                        if cid not in self.master_indicator_dict:
                            self.master_indicator_dict[cid] = { 'status' : 'New', 'type' : ctype, 'value' : cvalue, 'submitted' : False }
                            new_indicator_count += 1
                            self.add_indicator_to_modules(cid, ctype, cvalue)
                    total_indicator_count = len(self.master_indicator_dict.keys())

                if new_indicator_count > 0:
                    log.info('Found {} new indicators to analyze.'.format(new_indicator_count))
                    log.info('Master list size is now {}'.format(total_indicator_count))
                last_update_time = time.time()
                self.has_initial_data = True
                # log.debug('Master indicator list updated.')
            time.sleep(1)


    def add_indicator_to_modules(self, cid, ctype, cvalue):
        for module in self.modules:
            if ctype in module.get_valid_indicator_types():
                log.debug('Adding indicator {} to module {}'.format(cid, module.getName()))
                module.add_indicator(cid, ctype, cvalue)


    # This should only be called after update_indicator()
    # This removes any indicator from the list that has a status of 'In Progress' or 'Analyzed'
    def clean_master_and_modules(self):
        ids_to_remove = []
        was_modified = False
        total_indicator_count = 0
        with self.master_indicator_lock:
            for cid in self.master_indicator_dict.keys():
                if self.master_indicator_dict[cid]['submitted']:
                    ids_to_remove.append(cid)

            for cid in ids_to_remove:
                self.master_indicator_dict.pop(cid)
                was_modified = True

            total_indicator_count = len(self.master_indicator_dict.keys())

        # Now remove from the modules
        for module in self.modules:
            for cid in ids_to_remove:
                module.remove_indicator(cid)

        if was_modified:
            log.info('Master list size is now {}'.format(total_indicator_count))
