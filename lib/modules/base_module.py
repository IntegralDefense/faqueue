import threading
import logging

from threading import Lock

log = logging.getLogger()

class BaseModule(threading.Thread):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.crits_data = { 'module_status' : 'not initialized' }
        self.data_lock = Lock()
        pass


    def run(self):
        pass


    def stop(self):
        pass


    def set_crits_data(self, crits_data):
        with self.data_lock:
            self.crits_data = crits_data


    def get_valid_indicator_types(self):
        return []


    def poll(self):
        return { 'module_status' : 'not initialized' }


    def get_module_status(self):
        return self.crits_data['module_status']


    def add_indicator(self, indicator_objectid, indicator_type, indicator_value):
        if self.has_indicator(indicator_objectid):
            log.warning('Tried to add an indicator {}, this module already '\
                        '{} has it!'.format(indicator_objectid, self.name))
            return False
        if indicator_type not in self.get_valid_indicator_types():
            log.warning('Tried to add indicator {} with type {} to module {}. \
            This is not a valid type!'.format(indicator_objectid, indicator_type, self.name))
            return False
        with self.data_lock:
            self.crits_data['indicators'][indicator_objectid] = {
                'type' : indicator_type,
                'value' : indicator_value,
                'status' : 'New',
                'completed' : False,
                'processing_results' : False,
                'results' : []
                }
        return True


    def check_indicator_status(self, indicator_objectid):
        if not self.has_indicator(indicator_objectid):
            return False
        with self.data_lock:
            status = self.crits_data['indicators'][indicator_objectid]['status']
        return status


    def get_indicator_data(self, indicator_objectid):
        if not self.has_indicator(indicator_objectid):
            return False
        with self.data_lock:
            if indicator_objectid not in self.crits_data['indicators']:
                return False
            indicator_data = self.crits_data['indicators'][indicator_objectid]
        return indicator_data


    def remove_indicator(self, indicator_objectid):
        if not self.has_indicator(indicator_objectid):
            return False
        with self.data_lock:
            return_data = self.crits_data['indicators'].pop(indicator_objectid, False)
        return return_data


    def has_indicator(self, indicator_objectid):
        with self.data_lock:
            if 'indicators' not in self.crits_data:
                log.error('indicators key not found in crits_data.')
                return False
            if indicator_objectid in self.crits_data['indicators'].keys():
                return True
        return False
