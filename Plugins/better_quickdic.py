from pwnagotchi import plugins
import logging
import subprocess
import shlex
import re
import os
import glob
import threading
import json

from flask import render_template_string, Response


TEMPLATE = """
{% extends "base.html" %}
{% set active_page = "plugins" %}

{% block title %}QuickDic{% endblock %}

{% block styles %}
{{ super() }}
<style>
    .qd-header {
        padding: 20px 0 10px;
    }
    .qd-header h2 {
        font-family: var(--font-pixel);
        color: var(--accent);
        font-size: 1.5rem;
        margin-bottom: 8px;
    }
    .qd-stats {
        display: flex;
        gap: 16px;
        flex-wrap: wrap;
        margin-bottom: 20px;
    }
    .qd-stat {
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 12px 20px;
        text-align: center;
        min-width: 100px;
    }
    .qd-stat .num {
        font-family: var(--font-pixel);
        font-size: 1.8rem;
        font-weight: bold;
    }
    .qd-stat .label {
        font-size: 0.75rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .qd-stat.cracked .num { color: #50fa7b; }
    .qd-stat.failed .num { color: #ff5555; }
    .qd-stat.cracking .num { color: #f1fa8c; }
    .qd-stat.total .num { color: var(--accent); }

    .table-container {
        background-color: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        overflow: hidden;
        box-shadow: var(--shadow-md);
    }
    table {
        width: 100%;
        border-collapse: collapse;
    }
    th {
        padding: 14px 16px;
        text-align: left;
        color: var(--accent);
        font-weight: 600;
        font-family: var(--font-pixel);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        font-size: 0.85rem;
        border-bottom: 2px solid var(--border-color);
    }
    td {
        padding: 12px 16px;
        border-bottom: 1px solid var(--border-color);
        color: var(--text-body);
        font-size: 0.9rem;
    }
    tbody tr:hover {
        background-color: rgba(var(--accent-r), var(--accent-g), var(--accent-b), 0.05);
    }
    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.78rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.3px;
    }
    .badge.cracked { background: rgba(80,250,123,0.15); color: #50fa7b; }
    .badge.failed { background: rgba(255,85,85,0.15); color: #ff5555; }
    .badge.cracking { background: rgba(241,250,140,0.15); color: #f1fa8c; }
    .badge.pending { background: rgba(136,136,136,0.15); color: #888; }

    .pwd { font-family: 'Courier New', monospace; color: #50fa7b; font-weight: bold; }
    .empty-state {
        text-align: center;
        padding: 60px 20px;
        color: var(--text-muted);
    }
    .empty-state .icon { font-size: 3rem; margin-bottom: 12px; }

    @media screen and (max-width: 600px) {
        .qd-stats { gap: 8px; }
        .qd-stat { min-width: 70px; padding: 8px 12px; }
        .qd-stat .num { font-size: 1.3rem; }
        th, td { padding: 10px 10px; font-size: 0.82rem; }
        .bssid-col { display: none; }
    }
</style>
{% endblock %}

{% block content %}
<div class="qd-header">
    <h2>QuickDic - Handshake Cracker</h2>
</div>

<div class="qd-stats" id="stats">
    <div class="qd-stat total"><div class="num" id="s-total">-</div><div class="label">Total</div></div>
    <div class="qd-stat cracked"><div class="num" id="s-cracked">-</div><div class="label">Cracked</div></div>
    <div class="qd-stat failed"><div class="num" id="s-failed">-</div><div class="label">Failed</div></div>
    <div class="qd-stat cracking"><div class="num" id="s-active">-</div><div class="label">Active</div></div>
</div>

<div class="table-container" id="table-wrap">
    <table>
        <thead>
            <tr>
                <th>Network</th>
                <th class="bssid-col">BSSID</th>
                <th>Status</th>
                <th>Password</th>
            </tr>
        </thead>
        <tbody id="results"></tbody>
    </table>
</div>

<div class="empty-state" id="empty" style="display:none;">
    <div class="icon">( ._.)</div>
    <div>No handshakes captured yet. Go hunt some!</div>
</div>
{% endblock %}

{% block script %}
function escHtml(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
}

function refresh() {
    fetch('/plugins/better_quickdic/api/status')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var hs = data.handshakes;
            var tbody = document.getElementById('results');
            var empty = document.getElementById('empty');
            var tableWrap = document.getElementById('table-wrap');

            document.getElementById('s-total').textContent = data.total;
            document.getElementById('s-cracked').textContent = data.cracked;
            document.getElementById('s-failed').textContent = data.failed;
            document.getElementById('s-active').textContent = data.cracking;

            if (hs.length === 0) {
                tbody.innerHTML = '';
                tableWrap.style.display = 'none';
                empty.style.display = '';
                return;
            }
            tableWrap.style.display = '';
            empty.style.display = 'none';

            var html = '';
            for (var i = 0; i < hs.length; i++) {
                var h = hs[i];
                var badge = '<span class="badge ' + h.status + '">' + h.status + '</span>';
                var pwd = h.password ? '<span class="pwd">' + escHtml(h.password) + '</span>' : '-';
                html += '<tr>'
                    + '<td>' + escHtml(h.name) + '</td>'
                    + '<td class="bssid-col">' + escHtml(h.bssid) + '</td>'
                    + '<td>' + badge + '</td>'
                    + '<td>' + pwd + '</td>'
                    + '</tr>';
            }
            tbody.innerHTML = html;
        })
        .catch(function(e) { console.error('quickdic refresh:', e); });
}

refresh();
setInterval(refresh, 10000);
{% endblock %}
"""


class QuickDic(plugins.Plugin):
    __author__ = 'silentree12th'
    __version__ = '3.0.0'
    __license__ = 'GPL3'
    __description__ = 'Run a quick dictionary scan against captured handshakes with web UI dashboard.'
    __dependencies__ = {
        'apt': ['aircrack-ng'],
    }
    __defaults__ = {
        'enabled': True,
        'wordlist_folder': '/home/pi/wordlists/',
        'face': '(·ω·)',
    }

    def __init__(self):
        self._cracking = set()
        self._cracked = set()

    def on_loaded(self):
        logging.info('[quickdic] plugin loaded')

        if 'face' not in self.options:
            self.options['face'] = '(·ω·)'
        if 'wordlist_folder' not in self.options:
            self.options['wordlist_folder'] = '/home/pi/wordlists/'

        try:
            subprocess.run(['/usr/bin/aircrack-ng', '--help'],
                           capture_output=True, timeout=5)
            logging.info('[quickdic] aircrack-ng found')
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logging.warning('[quickdic] aircrack-ng is not installed!')

        # load already-cracked and failed files so we don't re-attempt
        for cracked_file in glob.glob('/home/pi/handshakes/*.cracked'):
            self._cracked.add(cracked_file.replace('.cracked', ''))
        for failed_file in glob.glob('/home/pi/handshakes/*.failed'):
            self._cracked.add(failed_file.replace('.failed', ''))

    def _get_wordlists(self):
        folder = self.options['wordlist_folder']
        wordlists = sorted(glob.glob(os.path.join(folder, '*.txt')))
        return ','.join(wordlists) if wordlists else None

    def _get_handshake_status(self):
        results = []
        for pcap in sorted(glob.glob('/home/pi/handshakes/*.pcap')):
            basename = os.path.basename(pcap)
            # bettercap format: "NetworkName_aabbccddeeff.pcap"
            if '_' in basename:
                name_part = basename.rsplit('_', 1)[0]
                bssid_raw = basename.rsplit('_', 1)[1].replace('.pcap', '')
            else:
                name_part = basename.replace('.pcap', '')
                bssid_raw = ''

            if len(bssid_raw) == 12:
                bssid = ':'.join(bssid_raw[i:i+2] for i in range(0, 12, 2)).upper()
            else:
                bssid = bssid_raw

            cracked_file = pcap + '.cracked'
            failed_file = pcap + '.failed'

            if os.path.exists(cracked_file):
                try:
                    with open(cracked_file, 'r') as f:
                        password = f.read().strip()
                except OSError:
                    password = '?'
                status = 'cracked'
            elif pcap in self._cracking:
                password = ''
                status = 'cracking'
            elif os.path.exists(failed_file):
                password = ''
                status = 'failed'
            else:
                password = ''
                status = 'pending'

            results.append({
                'name': name_part,
                'bssid': bssid,
                'status': status,
                'password': password,
                'file': basename,
            })
        return results

    def on_webhook(self, path, request):
        if not path or path == '/':
            return render_template_string(TEMPLATE)

        if path == 'api/status':
            handshakes = self._get_handshake_status()
            counts = {'total': len(handshakes), 'cracked': 0, 'failed': 0, 'cracking': 0}
            for h in handshakes:
                if h['status'] in counts:
                    counts[h['status']] += 1
            data = {**counts, 'handshakes': handshakes}
            return Response(json.dumps(data), mimetype='application/json')

        from flask import abort
        abort(404)

    def _crack_handshake(self, agent, filename, access_point, client_station):
        try:
            wordlists = self._get_wordlists()
            if not wordlists:
                logging.warning('[quickdic] no wordlists found in %s', self.options['wordlist_folder'])
                return

            cracked_file = filename + '.cracked'

            result = subprocess.run(
                ['nice', '-n', '15', '/usr/bin/aircrack-ng',
                 '-w', wordlists,
                 '-l', cracked_file,
                 '-q', filename],
                capture_output=True, timeout=600
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
            else:
                logging.info('[quickdic] key not found for %s', filename)
                try:
                    with open(filename + '.failed', 'w') as f:
                        f.write('')
                except OSError:
                    pass

        except subprocess.TimeoutExpired:
            logging.warning('[quickdic] aircrack-ng timed out for %s', filename)
            try:
                with open(filename + '.failed', 'w') as f:
                    f.write('')
            except OSError:
                pass
        except Exception as e:
            logging.error('[quickdic] error cracking %s: %s', filename, e)
        finally:
            self._cracking.discard(filename)

    def on_handshake(self, agent, filename, access_point, client_station):
        if filename in self._cracked or filename in self._cracking:
            return

        self._cracked.add(filename)
        self._cracking.add(filename)

        t = threading.Thread(
            target=self._crack_handshake,
            args=(agent, filename, access_point, client_station),
            daemon=True
        )
        t.start()
        logging.info('[quickdic] cracking %s in background', filename)
