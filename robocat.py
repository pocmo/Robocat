#!/usr/bin/python -u

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Script to read, parse and highlight robocop messages from logcat output

# This code is heavily based on "pidcat" by Jake Wharton, which is based
# on code written by Jeff Sharkey and improved by other Android team
# members. TL;DR: Open-source rocks!

import argparse
import sys
import re
import subprocess
import json
import datetime

from subprocess import PIPE

__version__ = '1.0.0'

ROBOCOP_TAG = 'Robocop'

parser = argparse.ArgumentParser(description='Readable robocop logcat')
parser.add_argument('package', nargs='*', help='Application package name(s)')
parser.add_argument('-s', '--serial', dest='device_serial', help='Device serial number (adb -s option)')
parser.add_argument('-d', '--device', dest='use_device', action='store_true', help='Use first device for log input (adb -d option)')
parser.add_argument('-e', '--emulator', dest='use_emulator', action='store_true', help='Use first emulator for log input (adb -e option)')
parser.add_argument('-c', '--clear', dest='clear_logcat', action='store_true', help='Clear the entire log before running')
parser.add_argument('-i', '--ignore-tag', dest='ignored_tag', action='append', help='Filter output by ignoring specified tag(s)')
parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__, help='Print the version number and exit')
parser.add_argument('--debug', dest='debug_output', action='store_true', help='Print raw JSON for debugging')

args = parser.parse_args()

package = args.package

base_adb_command = ['adb']
if args.device_serial:
  base_adb_command.extend(['-s', args.device_serial])
if args.use_device:
  base_adb_command.append('-d')
if args.use_emulator:
  base_adb_command.append('-e')


# Store the names of packages for which to match all processes.
catchall_package = filter(lambda package: package.find(":") == -1, package)
# Store the name of processes to match exactly.
named_processes = filter(lambda package: package.find(":") != -1, package)
# Convert default process names from <package>: (cli notation) to <package> (android notation) in the exact names match group.
named_processes = map(lambda package: package if package.find(":") != len(package) - 1 else package[:-1], named_processes)

width = -1
try:
  # Get the current terminal width
  import fcntl, termios, struct
  h, width = struct.unpack('hh', fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('hh', 0, 0)))
except:
  pass

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

RESET = '\033[0m'

def termcolor(fg=None, bg=None):
  codes = []
  if fg is not None: codes.append('3%d' % fg)
  if bg is not None: codes.append('10%d' % bg)
  return '\033[%sm' % ';'.join(codes) if codes else ''

def colorize(message, fg=None, bg=None):
  return termcolor(fg, bg) + message + RESET

ROBOCOP_LOG_LEVELS = {
  'unknown': colorize(' ? ', fg=WHITE, bg=CYAN),
  'info':    colorize(' I ', fg=WHITE, bg=BLUE),
  'debug':   colorize(' D ', fg=WHITE, bg=BLACK),
  'warn':    colorize(' W ', fg=BLACK, bg=YELLOW),
  'error':   colorize(' E ', fg=BLACK, bg=RED)
}

PID_LINE = re.compile(r'^\w+\s+(\w+)\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w\s([\w|\.]+)$')
LOG_LINE  = re.compile(r'^([A-Z])/(.+?)\( *(\d+)\): (.*?)$')
BUG_LINE  = re.compile(r'.*nativeGetEnabledTags.*')

adb_command = base_adb_command[:]
adb_command.append('logcat')
adb_command.extend(['-v', 'brief'])

# Clear log before starting logcat
if args.clear_logcat:
  adb_clear_command = list(adb_command)
  adb_clear_command.append('-c')
  adb_clear = subprocess.Popen(adb_clear_command)

  while adb_clear.poll() is None:
    pass

# This is a ducktype of the subprocess.Popen object
class FakeStdinProcess():
  def __init__(self):
    self.stdout = sys.stdin
  def poll(self):
    return None

if sys.stdin.isatty():
  adb = subprocess.Popen(adb_command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
else:
  adb = FakeStdinProcess()
pids = set()
last_tag = None
app_pid = None


def parse_time(time):
  d = datetime.datetime.fromtimestamp(time / 1000)
  return d.strftime("[%H:%M:%S] ")


def format_message_log(robocop_message):
  message = parse_time(robocop_message['time'])
  message += colorize('      LOG    ', bg=WHITE)
  message += ROBOCOP_LOG_LEVELS.get(robocop_message['level'], ROBOCOP_LOG_LEVELS['unknown'])
  message += ' ' + robocop_message["message"]
  return message


def format_message_test_status(robocop_message):
  message = parse_time(robocop_message['time'])

  color = BLACK;

  message += colorize('     TEST ', bg=WHITE)
  if robocop_message['status'] == 'PASS':
    message += colorize(' PASS ', fg=BLACK, bg=GREEN) + ' '
    color = GREEN
  elif robocop_message['status'] == 'FAIL':
    message += colorize(' FAIL ', fg=BLACK, bg=RED) + ' '
    color = RED
  elif robocop_message['status'] == 'OK':
    message += colorize('  OK  ', fg=BLACK, bg=YELLOW) + ' '
    color = YELLOW
  
  message += colorize(robocop_message['subtest'], fg=color)

  if not 'message' in robocop_message:
    return None

  test_message = robocop_message['message'].strip()
  if test_message:
    message += '\n'
    message += '           '
    message += colorize('     TEST       ', bg=WHITE)
    message += ' ' + colorize(test_message, fg=color)

  return message


def format_message_test_start(robocop_message):
  message = parse_time(robocop_message['time'])
  message += colorize(' START' + ' ' * 10, bg=MAGENTA)
  message += ' ' + colorize(robocop_message['test'], fg=MAGENTA)
  return message


def format_message_test_end(message):
  message = parse_time(robocop_message['time'])
  message += colorize('  END ' + ' ' * 10, bg=CYAN)
  message += ' ' + colorize(robocop_message['test'], fg=CYAN)
  return message


def format_message_unknown(message):
  return json.dumps(message, sort_keys=True, indent=4)


def format_message_raw(raw_message):
  message = '           '
  message += colorize('      RAW       ', bg=WHITE)
  message += ' ' + raw_message
  return message

FORMAT_MAPPING = {
  "log": format_message_log,
  "test_status": format_message_test_status,
  "test_start": format_message_test_start,
  "test_end": format_message_test_end
}

ps_command = base_adb_command + ['shell', 'ps']
ps_pid = subprocess.Popen(ps_command, stdin=PIPE, stdout=PIPE, stderr=PIPE)

while ps_pid.poll() is None:
  try:
    line = ps_pid.stdout.readline().decode('utf-8', 'replace').strip()
  except KeyboardInterrupt:
    break
  if len(line) == 0:
    break

  pid_match = PID_LINE.match(line)
  if pid_match is not None:
    pid = pid_match.group(1)
    proc = pid_match.group(2)
    if proc in catchall_package:
      seen_pids = True
      pids.add(pid)

while adb.poll() is None:
  try:
    line = adb.stdout.readline().decode('utf-8', 'replace').strip()
  except KeyboardInterrupt:
    break
  if len(line) == 0:
    break

  bug_line = BUG_LINE.match(line)
  if bug_line is not None:
    continue

  log_line = LOG_LINE.match(line)
  if log_line is None:
    continue

  level, tag, owner, message = log_line.groups()
  tag = tag.strip()

  if tag != ROBOCOP_TAG:
    continue

  try: 
    robocop_message = json.loads(message)

    formatter = FORMAT_MAPPING.get(robocop_message['action'], format_message_unknown)
    message = formatter(robocop_message)

    if args.debug_output:
      print(format_message_unknown(robocop_message))
  except ValueError:
    message = format_message_raw(message)

  if message:
    print(message)
