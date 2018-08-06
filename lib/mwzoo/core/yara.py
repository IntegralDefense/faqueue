import json
import logging
import os
import yara

log = logging.getLogger()

class YaraScanner():
    def __init__(self, rules_dir='', rules_file=''):
        self.rules_dir = rules_dir
        self.rules_file = rules_file
        self.source = {}
        self.sources = {}
        if self.rules_dir != '' and not os.path.isdir(self.rules_dir):
            log.error('Yara rules directory does not exist: {}'.format(self.rules_dir))
        if self.rules_file != '' and not os.path.exists(self.rules_file):
            log.error('Yara file does not exist: {}'.format(self.rules_file))
        if self.rules_dir != '':
            self._gather_dir_sources(rules_dir)
        if self.rules_file != '':
            self._gather_file_sources(rules_file)
        self.compiled = False
        self.compiled_rules = None

    def _gather_dir_sources(self, rule_path):
        if rule_path not in self.source:
            self.source[rule_path] = []
        for f in os.listdir(rule_path):
            f_path = os.path.join(rule_path, f)
            if f.lower().endswith('.yar'):
                try:
                    yara.compile(f_path)
                except Exception as e:
                    logging.error('Unable to compile rule: {} - Error was: {}'.format(f, e))
                    continue
                with open(f_path, 'r') as fp:
                    data = fp.read()
                    self.source[rule_path].append(data)
            elif os.path.isdir(f_path):
                results = self._gather_self.sources(f_path)
                for key in results.keys():
                    if key not in self.source:
                        self.source[key] = []
                    for result in results[key]:
                        self.source[key].append(result)

    def _gather_file_sources(self, rule_file):
        rule_path = os.path.dirname(rule_file)
        if rule_path not in self.source:
            self.source[rule_path] = []
        try:
            yara.compile(rule_file)
        except Exception as e:
            logging.error('Unable to compile rule: {} - Error was: '
                          '{}'.format(rule_file, e))
        with open(rule_file, 'r') as fp:
            data = fp.read()
            self.source[rule_path].append(data)

    def test_rules(self):
        return self.compile_rules()

    def compile_rules(self):
        for key in self.source.keys():
            self.sources[key] = '\r\n'.join(self.source[key])

        if not self.compiled_rules:
            try:
                self.compiled_rules = yara.compile(sources=self.sources)
            except Exception as e:
                log.error('Unable to compile all yara rules: {}'.format(e))
                return False
        self.compiled = True
        return True

    def run_scans(self, sample_paths=[]):
        all_results = { 'results' : [] }
        if not self.compiled:
            self.compile_rules()
        for sample in sample_paths:
            result = self.run_scan(sample)
            if result:
                all_results['results'].append(result)
        return all_results

    def run_scan(self, sample_path):
        if not self.compiled:
            self.compile_rules()
        results = None
        #log.debug('Scanning sample with yara: {}'.format(sample_path))
        try:
            results = self.compiled_rules.match(sample_path)
        except Exception as e:
            log.error('Error occurred while scanning file {}'.format(sample_path))
            log.error('Error was {}'.format(e))
            return None

        if not results:
            #log.debug('No results returned from yara.')
            return None

        #log.debug('Yara completed for sample with results: {}'.format(sample_path))
        yara_results = []
        for o in results:
            yr = {
                'target' : sample_path,
                'meta' : o.meta,
                'namespace' : o.namespace,
                'rule' : o.rule,
                'strings' : [],
                'tags' : o.tags
            }
            # Bullshit decode because yara decides to treat this one little thing as a byte
            for p in o.strings:
                success = False
                try:
                    strdec = p[2].decode('utf-8')
                    t = (p[0], p[1], strdec)
                    yr['strings'].append(t)
                except UnicodeDecodeError as e:
                    log.error('Error decoding utf-8 string: {0}'.format(p[2]))

            yara_results.append(yr)

        return yara_results
