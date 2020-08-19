#!/usr/bin/env python
usage = 'usage: %prog [options] email1 [email2 [...]]'
import logging, os, re,smtplib,remove_members, string, random, DNS

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

# Match the mail exchanger line in nslookup output.
#MX = re.compile(r'^.*\s+mail exchanger = (?P<priority>\d+) (?P<host>\S+)\s*$')
#MX = re.compile(r'(?P<priority>\d+) (?P<host>\S+)\s*$')
def verify(addr, local_addr='john.smith@example.com'):
  """Verify the existance of a single email address."""
  logging.debug('Verifying existance of %r', addr)
  # Find mail exchanger of this address.
  host = addr.rsplit('@', 2)[1]
  #p = os.popen('nslookup -q=mx %s' % host, 'r')
  #p = os.popen('dig %s MX +short' % host, 'r')
  # mxes = list()
  DNS.DiscoverNameServers()
  mxes = DNS.mxlookup(host)
  #for line in p:
  #  m = MX.match(line)
  #  if m is not None:
  #    mxes.append(m.group('host'))
  logging.debug('Found %d mail exchangers for %s.', len(mxes), host)
  logging.debug(mxes)
  if len(mxes) == 0:
    return False
  else:
    for num in mxes:
        smtp = smtplib.SMTP(timeout=5)
        try:
            logging.debug('trying %s.',num[1])
            smtp.connect(num[1])
        except (smtplib.SMTPConnectError,smtplib.socket.error):
           continue
        else:
           host = num[1]
           break
  logging.debug('final result = %s.',num[1])
  test_id = id_generator()
  # Connect to the mail server and check.
  logging.debug('Checking address with %s.', host)
  "print 'Checking address with %s.' % host"
  server = smtplib.SMTP(host,25,timeout=3)
  server.ehlo_or_helo_if_needed()
  code, response = server.docmd('mail from:', '<'+test_id+'@lists.nasa.gov>')
  logging.debug('MAIL FROM command <'+test_id+'@lists.nasa.gov>')
  logging.debug('MAIL FROM command returned %d: %r', code, response)
  "print 'MAIL FROM command returned %d: %r', code, response"
  code, response = server.docmd('rcpt to:', "<"+addr+">")
  logging.debug('RCPT TO command returned %d: %r', code, response)
  server.quit()
  return (code // 100 == 2)

def main(*args, **opts):
  """Handle execution from the command line."""
  for addr in args:
    if verify(addr, local_addr=opts['local_addr']):
      print '%r exists.' % addr
    else:
        print '%s DOES NOT exist.' % addr
        #os.system('/usr/lib/mailman/bin/remove_members.py -n -N --fromall %r' % addr )
        #os.system('/bin/mailq | tail -n+2 | awk \'BEGIN { RS = "" } /\'%r\'/ { print $1 }\' | tr -d \'*!\' | postsuper -d - ' % addr)
        #os.system('/bin/echo %r >> bad-users' % addr)

def flags():
  """Parse options from the command line."""
  from optparse import OptionParser
  parser = OptionParser(usage=usage)
  parser.add_option('-f', '--from',
      dest='local_addr', default='john.smith@example.com',
      help='email address to appear to be from')
  parser.add_option('-d', '--debug',
      action='store_const', const=logging.DEBUG, dest='log_level',
      help='log everything')
  parser.add_option('-v', '--verbose',
      action='store_const', const=logging.INFO, dest='log_level',
      help='log everything but debugging messages')
  parser.add_option('-q', '--quiet',
      action='store_const', const=logging.ERROR, dest='log_level',
      help='only log errors')
  opts, args = parser.parse_args()
  logging.basicConfig(level=opts.log_level)
  return opts, args

if __name__ == '__main__':
  opts, args = flags()
  main(*args, **opts.__dict__)
