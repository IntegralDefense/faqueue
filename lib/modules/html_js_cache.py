import os
import time
import json
import logging
import threading

from threading import Lock, Thread
from configparser import ConfigParser
  
from lib.constants import FA_HOME
from lib.modules import base_module
  
log = logging.getLogger()
 
class HtmlJsCache(base_module.BaseModule):
  
    def __init__(self):
        super().__init__(name='HtmlJsCache')
        log.info('Initializing HtmlJsCache module.')
        self.config = ConfigParser()
        self.config.read(os.path.join(FA_HOME, "etc", "config.ini"))
        # Read any configuration options you have specified in config.ini
        self.html_cache_path = self.config['module_html_js_cache']['html_cache']
        self.js_cache_path = self.config['module_html_js_cache']['js_cache']
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
                # Create a list of CRITs object IDs.
                cid_list = list(self.crits_data['indicators'].keys())
            unprocessed_cids = []
            for cid in cid_list:
                with self.data_lock:
                    if not self.crits_data['indicators'][cid]['completed']:
                        unprocessed_cids.append(cid)
  
            # Now we can start a thread to process them
            if len(unprocessed_cids) > 0:
                # YOUR CODE HERE to process indicators
                thread = Thread(target=self.scan_cache, name='HtmlJsCacheScanner')
                thread.start()

                while thread.is_alive() and self.running:
                    time.sleep(2)
            else:
                time.sleep(2)

    def scan_cache(self):
        with self.data_lock:
            cid_list = list(self.crits_data['indicators'].keys())
        for cid in cid_list:
            # Ignore processed indicators
            with self.data_lock:
                if self.crits_data['indicators'][cid]['completed']:
                    continue

            # Figure out which cache path to use based on the indicator type.
            with self.data_lock:
                indicator_type = self.crits_data['indicators'][cid]['type']
                indicator_value = self.crits_data['indicators'][cid]['value']
            cache_path = ''
            if 'JS' in indicator_type:
                log.info('Scanning JS cache for indicator {}'.format(cid))
                cache_path = self.js_cache_path
            else:
                log.info('Scanning HTML cache for indicator {}'.format(cid))
                cache_path = self.html_cache_path

            if cache_path:
                cached_files = os.listdir(cache_path)
                cached_files = [os.path.join(cache_path, f) for f in cached_files]

                #observables = []
                results = []
                for cached_file in cached_files:
                    try:
                        with open(cached_file) as f:
                            text = f.read()

                        # If we found the indicator, add the URL as a result.
                        if indicator_value in text:
                            data = json.loads(text)

                            #observables.append({'type': 'url', 'value': url})
                            results.append(data['url'])
                    except:
                        pass

                # If we got results (i.e.: indicator found in the cache), set the
                # indicator results to the list of URLs that hit and mark the status.
                if len(results) > 0:
                    log.info('Cache hit {} times for indicator {}'.format(len(results), cid))
                    with self.data_lock:
                        if 'results' not in self.crits_data['indicators'][cid]:
                            self.crits_data['indicators'][cid]['results'] = []
                        if 'observables' not in self.crits_data['indicators'][cid]:
                            self.crits_data['indicators'][cid]['observables'] = []
                        results_data = {}
                        results_data['hits'] = results
                        results_data['total_hits'] = len(results)
                        self.crits_data['indicators'][cid]['results'].append(results_data)

                        # Since we had results, set the status to In Progress and completed.
                        self.crits_data['indicators'][cid]['status'] = 'In Progress'
                        self.crits_data['indicators'][cid]['completed'] = True
                # Since we did not get any results, turn the indicator on.
                else:
                    log.info('Cache did not hit for indicator {}. Turning it on.'.format(cid))
                    self.crits_data['indicators'][cid]['status'] = 'Analyzed'
                    self.crits_data['indicators'][cid]['completed'] = True

    def stop(self):
        log.warning("Caught interrupt. Shutting down HtmlJsCache...")
        self.running = False
  
    def set_crits_data(self, crits_data):
        with self.data_lock:
            self.crits_data = crits_data
  
    def get_valid_indicator_types(self):
        # This returns a list of acceptible CRITs indicators types for this
        # module. Include ONLY types that your module is able to process!
        return [
            'String - HTML',
            'String - JS',
            'URI - Path'
        ]
  
    def poll(self):
        with self.data_lock:
            return self.crits_data
