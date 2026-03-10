from pwnagotchi import plugins
import logging
import subprocess
import shlex
import re
import os
import glob
import threading


class QuickDic(plugins.Plugin):
    __author__ = 'silentree12th'
    __version__ = '2.0.0'
    __license__ = 'GPL3'
    __description__ = 'Run a quick dictionary scan against captured handshakes. Optionally send found passwords over to telegram bot.'
    __dependencies__ = {
        'apt': ['aircrack-ng'],
    }
    __defaults__ = {
        'enabled': True,
        'wordlist_folder': '/home/pi/wordlists/',
        'face': '(·ω·)',
        'api': None,
        'id': None,
    }

    def __init__(self):
        self._cracking = set()  # files currently being cracked (thread-safe via GIL)
        self._cracked = set()   # files already cracked or attempted

    def on_loaded(self):
        logging.info('[quickdic] plugin loaded')

        if 'face' not in self.options:
            self.options['face'] = '(·ω·)'
        if 'wordlist_folder' not in self.options:
            self.options['wordlist_folder'] = '/home/pi/wordlists/'
        if 'api' not in self.options:
            self.options['api'] = None
        if 'id' not in self.options:
            self.options['id'] = None

        # check aircrack-ng is installed
        try:
            result = subprocess.run(['/usr/bin/aircrack-ng', '--help'],
                                    capture_output=True, timeout=5)
            logging.info('[quickdic] aircrack-ng found')
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logging.warning('[quickdic] aircrack-ng is not installed!')

        # load already-cracked files from .cracked marker files
        handshake_dir = os.path.dirname(self.options.get('wordlist_folder', '/home/pi/handshakes/'))
        for cracked_file in glob.glob('/home/pi/handshakes/*.cracked'):
            self._cracked.add(cracked_file.replace('.cracked', ''))

    def _get_wordlists(self):
        """Get comma-separated list of wordlist files."""
        folder = self.options['wordlist_folder']
        wordlists = sorted(glob.glob(os.path.join(folder, '*.txt')))
        return ','.join(wordlists) if wordlists else None

    def _crack_handshake(self, agent, filename, access_point, client_station):
        """Run aircrack-ng in background thread with low priority."""
        try:
            wordlists = self._get_wordlists()
            if not wordlists:
                logging.warning('[quickdic] no wordlists found in %s', self.options['wordlist_folder'])
                return

            cracked_file = filename + '.cracked'

            # run aircrack-ng at low priority (nice 15) to not starve the attack loop
            result = subprocess.run(
                ['nice', '-n', '15', '/usr/bin/aircrack-ng',
                 '-w', wordlists,
                 '-l', cracked_file,
                 '-q', filename],
                capture_output=True, timeout=600  # 10 min max
            )

            output = result.stdout.decode('utf-8', errors='replace').strip()

            if 'KEY FOUND' in output:
                key_match = re.search(r'\[(.*)\]', output)
                if key_match:
                    pwd = key_match.group(1)
                    logging.warning('[quickdic] cracked %s: %s', filename, pwd)

                    display = agent.view()
                    display.set('face', self.options['face'])
                    display.set('status', 'Cracked: ' + pwd)
                    display.update(force=True)

                    if self.options.get('api') and self.options.get('id'):
                        self._send_message(filename, pwd)
            else:
                logging.info('[quickdic] key not found for %s', filename)

        except subprocess.TimeoutExpired:
            logging.warning('[quickdic] aircrack-ng timed out for %s', filename)
        except Exception as e:
            logging.error('[quickdic] error cracking %s: %s', filename, e)
        finally:
            self._cracking.discard(filename)

    def on_handshake(self, agent, filename, access_point, client_station):
        # skip if already cracked or currently cracking
        if filename in self._cracked or filename in self._cracking:
            return

        self._cracked.add(filename)
        self._cracking.add(filename)

        # run in background thread so the attack loop continues
        t = threading.Thread(
            target=self._crack_handshake,
            args=(agent, filename, access_point, client_station),
            daemon=True
        )
        t.start()
        logging.info('[quickdic] cracking %s in background', filename)
