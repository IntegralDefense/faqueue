import logging
import sqlite3
import threading

from threading import Lock, Thread

log = logging.getLogger()

class AceObservables(base_module.BaseModule):

    def __init__(self):
        super().__init__(name='AceObservables')
        log.info('Initializing SplunkAshland module.')
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
        self.db_path = self.config.get('module_ace_observables', 'db_path')

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
                thread = Thread(target=self.run_sqlite_searches, name='AceObservablesSearch')
                thread.start()

                while thread.is_alive() and self.running:
                    time.sleep(2)
            else:
                time.sleep(2)


    def stop(self):
        log.warning("Caught interrupt. Shutting down AceObservables...")
        self.running = False


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
                ]


    def poll(self):
        with self.data_lock:
            return self.crits_data


    def run_sqlite_searches(self):
        log.info('Running AceObservable searches.')
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
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
                cursor.execute("SELECT * FROM observables WHERE value=?",
                           ('%'+self.crits_data['indicators'][cid]['value']+'%',))
                results = cursor.fetchall()
                log.info('Observable found {} times for indicator'
                         '{}'.format(len(results), cid))
                if len(results) > 0:
                    search = "SELECT * FROM observables WHERE value='%{}%".format(self.crits_data['indicators'][cid]['value'])
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
                        for result in results:
                            if current_count > self.results_limit:
                                break
                            current_count += 1
                            _results_data['hits'].append(result['value'])
