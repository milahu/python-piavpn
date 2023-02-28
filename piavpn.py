#!/usr/bin/env python3

# piavpn.py
# setup PIA VPN on linux
# https://www.privateinternetaccess.com/

# python version of
# https://github.com/pia-foss/manual-connections
# for now: only support for wireguard protocol, no openvpn
# license: CC0-1.0 author: milahu@gmail.com

# deps:
# pip install argparse cerberus pyyaml requests tzlocal pygeoip

import sys, os, argparse, cerberus, yaml, re, requests, datetime, tzlocal, \
  subprocess, json, asyncio, async_timeout, math, timeit, types, functools, \
  urllib, ipaddress, urllib.parse, base64, time, pygeoip

# local dep: forcediphttpsadapter.py
# from https://github.com/Roadmaster/forcediphttpsadapter
# instead of 100 lines forcediphttpsadapter,
# we could simply use `curl --connect-to fake_name::real_ip:`
# since this script works only on linux anyway

import forcediphttpsadapter

script_name = os.path.basename(sys.argv[0])
date_format = '%Y-%m-%d %H:%M:%S %z'



def main():

  args = parse_args()

  if os.path.isfile(args.config) == False:
    return config_not_found()

  config = parse_config(args.config)

  # todo these should work without config ...

  if args.regions == True:
    return show_regions(config)

  if args.servers == True:
    return show_servers(config)

  if config.usesudo == False:
    return require_root_user()

  print('login ...')
  token = get_token(config)
  print('login token: %s' % token)

  token_expire = date_now_plus(hours=24)
  print('login token will expire in 24 hours on %s' % token_expire)

  # todo use cached token if not expired?
  #write_token(config, token, token_expire)

  if config.disableipv6 == True:
    disable_ipv6(config)

  (server, region) = get_server_region(config)

  if config.protocol == 'wireguard':
    connect_to_wireguard(config, server, token, region)

  elif config.protocol == 'openvpn':
    connect_to_openvpn(config, server, token, region)

  if config.portforwarding:
    start_portforwarding(config, token, server)
  else:
    print('portforwarding is disabled')

  # todo loop `while True` and refresh login
  # combine loops: login every 24 hours + portforwarding every 15 minutes



def date_now():
  return datetime.datetime.now(tzlocal.get_localzone()
    ).strftime(date_format)

# sample kwargs: hours=24
def date_now_plus(**kwargs):
  return (
    datetime.datetime.now(tzlocal.get_localzone() ) +
    datetime.timedelta(**kwargs)
  ).strftime(date_format)

def parse_nanodate(s):
  """
  parse date, ignore nanoseconds
  sample input: 2020-12-31T16:20:00.000000123Z
  --> 123ns will be ignored
  """
  print(f"parse_nanodate: 1: s = {s}")
  # ok 2022-10-17T00:51:59.353237574Z
  # !! 2022-11-25T07:36:48.46057555Z # bad
  # !! 2023-04-23T03:24:41.6293472Z # bad
  left, right = s.split("Z")
  left = left.ljust(29, "0")
  s = left + right
  if 'Z' not in s:
    s += 'Z'
  print(f"parse_nanodate: 2: s = {s}")
  if s[-1] == 'Z':
    # add explicit UTC timezone, to make strptime happy
    s += '+0000'
  # ok 2022-10-17T00:51:59.353237574Z+0000
  print(f"parse_nanodate: 3: s = {s}")
  s = s[0:26] + s[29:]
  print(f"parse_nanodate: 4: s = {s}")
  return datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%fZ%z')
  # FIXME 2022-10-17T00:46:15.503790+0000 -> parse error
  # ok    2022-10-17T00:51:59.353237Z+0000

def format_date(d):
  return d.astimezone(tzlocal.get_localzone()).strftime(date_format)

# this will loop forever
def start_portforwarding(config, token, server):
  if config.protocol == 'openvpn':
    # openvpn: pf_gateway=gateway_ip=$(cat /opt/piavpn-manual/route_info)
    # .. but that file is never written?
    return print('error. portforwarding not yet supported for openvpn')

  print('portforwarding: get new signature ...')
  res = call_api(server, 19999, 'getSignature', token=token)
  if res.status != 'OK':
    die(f'portforwarding: failed to getSignature')

  payload = namespace_from_json(base64.b64decode(res.payload)) # .decode('utf8')

  # parse + reformat date
  payload.expires_at_date = parse_nanodate(payload.expires_at)
  payload.expires_at = format_date(payload.expires_at_date)

  print(f'portforwarding: Received port {payload.port} '
    f'expires on {payload.expires_at}')
  last_res = res

  print(f'portforwarding: bind port {payload.port} every 15 minutes ...')
  while True:
    res = call_api(server, 19999, 'bindPort',
      payload=last_res.payload, signature=last_res.signature)
    if res.status != 'OK':
      print(f'portforwarding: failed to bindPort')
    else:
      print(f'refreshed port {payload.port} on {date_now()}. '
        f'expires on {payload.expires_at}')
    try:
      time.sleep(900) # wait 15 minutes
    except KeyboardInterrupt:
      die('got KeyboardInterrupt. exit')
    # todo: handle port expired --> get new port
    # allow to run custom commands (defined in yaml config file)
    # for example: update port of bittorrent client

def get_server_region(config):
  server_list = None
  region = None
  if str(config.server) != 'namespace()':
    server_list = namespace_from_object(
      [{ 'ip': config.server.ip, 'cn': config.server.name }])
  else:
    print('Getting full server list ... (to disable, set server)')
    full_server_list = get_full_server_list(config)
    if config.region != '':
      print('Using region: ' + config.region)
      region = get_region(full_server_list, config.region)
    else:
      print('Finding nearest region ... (to disable, set server or region)')
      region = get_nearest_regions_list(config, full_server_list)[-1][1]
      debug('Found nearest region: ' + region.name)
    server_type = get_server_type(config)
    server_list = getattr(region.servers, server_type)
  server = server_list[0] # todo future: choose from list
  print('Using server: ' + repr(server))
  return (server, region)

# send API call via HTTPS GET request, parse JSON response
def call_api(server, port, path, **kwargs):
  # needed to force hostname + IP
  # compare: curl --connect-to server_cn::server_ip:
  protocol = 'https'
  session = requests.Session()
  session.mount(f'{protocol}://{server.cn}:{port}',
    forcediphttpsadapter.ForcedIPHTTPSAdapter(dest_ip=server.ip))
  query = urllib.parse.urlencode(kwargs)
  res = namespace_from_json(session.get(
    f'{protocol}://{server.cn}:{port}/{path}?' + query,
    headers={'Host': server.cn}, verify=rpc_cert_file).text)
  if res.status != 'OK':
    debug(f'call_api failed at {protocol}://{server.cn}:{port}/{path}')
    debug(f'call_api query: {repr(kwargs)}')
    debug(f'call_api response: {repr(res)}')
  return res

def connect_to_openvpn(config, server, token, region):
  die('todo implement')
  # todo: handle openvpn.encryption

def connect_to_wireguard(config, server, token, region):
  private_key = exec(['wg', 'genkey'])
  public_key = exec(['wg', 'pubkey'], input=(private_key+'\n').encode('utf8'))
  debug('wireguard public key: '+public_key)
  res = call_api(server, 1337, 'addKey', pt=token, pubkey=public_key)
  if res.status != 'OK':
    die('failed on wireguard addkey')
  print(repr(res))
  # unused
  #res.server_vip == '12.34.56.78'
  #res.peer_pubkey == 'cACHgasdfuk0asdf/SCasdf8evijasdfasdfTZoasdf='

  print('Disabling old Wireguard connection ...')
  exec(['wg-quick', 'down', 'pia'], check=False, capture_output=False)

  pia_conf_dns = f'DNS = {res.dns_servers[0]}' if config.setdns else ''
  pia_conf = f"""\
# generated by {script_name}

[Interface]
Address = {res.peer_ip}
PrivateKey = {private_key}
{pia_conf_dns}

[Peer]
PersistentKeepalive = 25
PublicKey = {res.server_key}

# TODO why?
# required for wg-quick, but breaks with wg-netns
AllowedIPs = 0.0.0.0/0

Endpoint = {res.server_ip}:{res.server_port}
"""

  print('Write /etc/wireguard/pia.conf')
  exec(['sudo', 'mkdir', '-p', '/etc/wireguard'], check=False)
  exec(['sudo', 'tee', '/etc/wireguard/pia.conf'], input=(pia_conf+'\n').encode('utf8'))

  # todo: no need for sudo?
  print('Create the Wireguard interface ...')
  exec(['wg-quick', 'up', 'pia'], capture_output=False)

  # test IP and country
  actual_ip = test_public_ip(res.server_ip)

  # TODO set config.geoipdb from env GEOIPDB
  #if region:
  #  test_country(config, actual_ip, region)

  print('To disconnect from the VPN, run: wg-quick down pia')

def test_country(config, actual_ip, region):
  # todo: test if db file exists
  db = pygeoip.GeoIP(config.geoipdb, flags=pygeoip.const.MMAP_CACHE)
  cc = db.country_code_by_addr(actual_ip)
  if cc == region.country:
    print(f'success: our public IP is in country {cc}')
  else:
    print(f'error: our public IP is in country {cc} but should be in country {region.country}')

def test_public_ip(expected_ip):
  # FIXME DNS error
  actual_ip = requests.get('https://api64.ipify.org?format=json').json()['ip']
  if actual_ip == expected_ip:
    print(f'success: now we have the same public IP as our VPN server: {expected_ip}')
  else:
    print(f'error: we have a different public IP {actual_ip} that of our VPN server {expected_ip}')
  return actual_ip

gettoken_url = 'https://privateinternetaccess.com/gtoken/generateToken'
full_server_list_url = 'https://serverlist.piaservers.net/vpninfo/servers/v4'
rpc_cert_file = 'ca.rsa.4096.crt'

import shlex

# this is a mess .... but it works :P
def exec(cmd, **kwargs):
  check = False
  if 'check' in kwargs:
    check = kwargs['check']
    del(kwargs['check'])
  if not 'capture_output' in kwargs:
    kwargs['capture_output'] = True
  res = subprocess.run(
    cmd,
    **kwargs
  )
  print("exec:", shlex.join(cmd))
  if check and res.returncode != 0:
    # correctly interleaving stdout+stderr is crazy complicated ..
    # easier: set capture_output=False
    if kwargs['capture_output']:
      print(res.stdout.decode('utf8'))
      print(res.stderr.decode('utf8'))
    raise Exception(f'returncode {res.returncode}')
  if kwargs['capture_output']:
    return res.stdout.decode('utf8').strip()

def get_server_list(config, region):
  server_type = get_server_type(config)
  return getattr(region.servers, server_type)

def get_region(full_server_list, region_id):
  return next(r for r in full_server_list.regions if r.id == region_id)

# ping many servers in parallel, aka netselect / mirrorselect
# https://github.com/anhenghuang/AsyncTCPPing
def async_tcp_ping(host_list, maxlatency, runs=10):
  async def worker(host, port, timeout=10, runs=1):
    res = []
    for run_id in range(0, runs):
      time_start = timeit.default_timer()
      try:
        # FIXME error=TypeError("timeout() got an unexpected keyword argument 'timeout'")
        #with async_timeout.timeout(timeout):
        async with async_timeout.timeout(timeout):
          #print(f'host={host}||port={port}||status=start')
          await asyncio.open_connection(host, port)
      except (asyncio.TimeoutError, OSError) as e:
        #print(f'host={host}||port={port}||status=error_end||error={repr(e)}')
        res.append(math.inf)
        continue
      except Exception as e:
        print(f'host={host}||port={port}||status=error_end||error={repr(e)}')
        #raise e # TODO why does this propagate to the result?
      time_end = timeit.default_timer()
      time_cost_milliseconds = (time_end - time_start) * 1000.0
      #print(f'host={host}||port={port}||status=end||timecost={time_cost_milliseconds}')
      res.append(time_cost_milliseconds)
    return min(res) # use best result
  port = 443

  # FIXME DeprecationWarning: There is no current event loop
  loop = asyncio.get_event_loop()
  #try:
  #  asyncio.run(main())
  #except KeyboardInterrupt:
  #  pass

  task_list = [
    loop.create_task(
      worker(host, port, timeout=maxlatency/1000.0, runs=runs)
    ) for host in host_list
  ]
  res = loop.run_until_complete(
    asyncio.gather(*task_list, return_exceptions=True)
  )
  loop.close()
  return res

def get_nearest_regions_list(config, full_server_list, print_result):
  debug('find nearest region ... (latency under %dms)' % config.maxlatency)
  # error: AttributeError: 'types.SimpleNamespace' object has no attribute 'meta'
  #host_list = [r.servers.meta[0].ip for r in full_server_list.regions]
  host_list = []
  for r in full_server_list.regions:
    try:
      host_list.append(r.servers.meta[0].ip)
    except AttributeError as e:
      print("region has no r.servers.meta[0].ip:", e, r)
      pass
  ping_list = async_tcp_ping(host_list, config.maxlatency, 50)
  # sort and filter
  ping_region_list = zip(ping_list, full_server_list.regions)
  ping_region_list = sorted(
    ping_region_list, key=lambda x: x[0], reverse=True)
  ping_region_list = [
    pr for pr in ping_region_list if pr[0] <= config.maxlatency]
  if print_result:
    for (ping, region) in ping_region_list:
      print('%.2fms %s (%s)' % (ping, region.id, region.name))
  #return ping_region_list[-1][1] # nearest region
  return ping_region_list

# https://stackoverflow.com/a/50491346/10440128
def namespace_from_json(str):
  def dict_to_sns(d):
    return types.SimpleNamespace(**d)
  return json.loads(str, object_hook=dict_to_sns)

def get_full_server_list(config):
  debug('getting full server list from ' + full_server_list_url)
  res_lines = requests.get(full_server_list_url).text.split('\n')
  full_server_list = namespace_from_json(res_lines[0])
  if (config.portforwarding == True):
    full_server_list.regions = [
      r for r in full_server_list.regions if r.port_forward == True
    ]
  #full_server_list.signature = '\n'.join(res_lines[1:]) # TODO whats this?
  return full_server_list
  # not used:
  # region.country = 'XX'
  # region.auto_region = true | false
  # region.dns = 'some.domain.name'
  # region.geo = true | false

# get key in regions[i].servers object
def get_server_type(config):
  if config.protocol == 'wireguard':
    return 'wg'
  if config.protocol == 'openvpn':
    if config.openvpn.protocol == 'tcp':
      return 'ovpntcp'
    return 'ovpnudp'
  return 'meta'
  # todo: what is ikev2 key?

def show_regions(config):
  print('Getting region list, sorted by latency ...')
  full_server_list = get_full_server_list(config)
  if config.yellow_regions:
    full_server_list.regions = list(filter(lambda r: (r.id in green_regions or r.id in yellow_regions), full_server_list.regions))
  ping_region_list = get_nearest_regions_list(config, full_server_list, False)
  #server_type = get_server_type(config)
  longest_region_id = max(len(pr[1].id) for pr in ping_region_list)
  print(f'longest_region_id = {longest_region_id}')
  # print in YAML format, same as in config file
  for (ping, region) in ping_region_list:
    space = (longest_region_id - len(region.id))*' '
    if region.id.replace('-', '_') == region.name.lower().replace(' ', '_'):
      print(f"region: {region.id} {space}# {ping:.2f}ms")
    else:
      print(f"region: {region.id} {space}# {ping:.2f}ms # {region.name}")

def show_servers(config):
  print('Getting server list, sorted by latency ...')
  full_server_list = get_full_server_list(config)
  ping_region_list = get_nearest_regions_list(config, full_server_list, False)
  server_type = get_server_type(config)
  # print in YAML format, same as in config file
  for (ping, region) in ping_region_list:
    print(f'# region: {region.id} ({region.name})')
    print(f'# latency: {ping:.2f}ms')
    for server in getattr(region.servers, server_type):
      print(f"protocol: {config.protocol}")
      if config.protocol == 'openvpn':
        print(f"openvpn.protocol: {config.openvpn.protocol}")
      print(f"server:\n  name: {server.cn}\n  ip: {server.ip}")
      print()

def debug(message):
  print('Debug: %s' % message)

def die(message):
  print(message)
  sys.exit(1)

def require_root_user():
  if os.getuid() != 0:
    die('with config `usesudo: false` you must run this script as root, '
      f'like: sudo {script_name}')

def parse_args():
  parser = argparse.ArgumentParser(description='Start PIA-VPN client')
  parser.add_argument('--config', '-c', default='/etc/piavpn.yaml',
    help='config file. default: %(default)s')
  parser.add_argument('--regions', action='store_true',
    help='Show all regions, sorted by latency')
  parser.add_argument('--servers', action='store_true',
    help='Show all servers, sorted by latency')
  args = parser.parse_args()
  debug('parsed CLI arguments: %s' % repr(vars(args)))
  return args

def parse_config(file_path):
  debug('reading config file: %s' % file_path)
  config_file = open(file_path, 'r')

  config = None
  try:
    config = yaml.full_load(config_file)
  except yaml.YAMLError as error:
    die(error)
  config_file.close()
  debug('done reading config: %s' % repr(config)) # todo redact password

  config = validate_config(config)

  # more validation
  if str(config.server) != 'namespace()' and config.region != '':
    die(f'error in config: you cannot set both server and region. server={repr(config.server)} region={repr(config.region)}')
  if config.protocol == 'wireguard':
    require_command('wg-quick',
      'the program wg-quick is required with protocol: wireguard')
    if config.setdns == True:
      require_command('resolvconf',
        'the program resolvconf is required with setdns: true and '
        'protocol: wireguard')
  if config.protocol == 'openvpn':
    require_command('openvpn',
      'the program openvpn is required with protocol: openvpn')

  return config

def validate_config(config):
  v = ConfigValidator(config_schema)
  if v.validate(config) == False:
    die('wrong config: %s' % repr(v.errors))
  debug('config is valid')
  return namespace_from_object(v.normalized(config))

def namespace_from_object(obj):
  @functools.singledispatch
  def wrap_namespace(ob):
    return ob
  @wrap_namespace.register(dict)
  def _wrap_dict(ob):
    return types.SimpleNamespace(
      **{k: wrap_namespace(v) for k, v in ob.items()})
  @wrap_namespace.register(list)
  def _wrap_list(ob):
    return [wrap_namespace(v) for v in ob]
  return wrap_namespace(obj)

def get_token(config):
  auth = auth=requests.auth.HTTPBasicAuth(config.username, config.password)
  res = requests.get(gettoken_url, auth=auth).json()
  if res['status'] != 'OK':
    die('failed to get token: %s' % repr(res))
  return res['token']

""" not used
def write_token(config, token, token_expire):
  os.makedirs(os.path.dirname(config.tokenfile), exist_ok=True)
  f = open(config.tokenfile, 'w')
  f.write('%s\n%s\n' % (token, token_expire))
  f.close()
"""

def require_command(command, error_message=None):
  try:
    subprocess.run(
      command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
  except Exception as error:
    print('failed to run command `%s`: %s' % (command, repr(error)))
    if error_message == None:
      sys.exit(1)
    die(error_message)

def disable_ipv6(config):
  res = subprocess.run(
    '%ssysctl -w '
    'net.ipv6.conf.all.disable_ipv6=1 '
    'net.ipv6.conf.default.disable_ipv6=1'
    % 'sudo ' if config.usesudo == True else '',
    shell=True
  )
  if res.returncode != 0:
    die('failed to disable ipv6')
  print('IPv6 is now disabled. to enable IPv6 again, run:')
  print('sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 '
    'net.ipv6.conf.default.disable_ipv6=0')

def test_ipv6():
  res = subprocess.run(
    'sysctl -n '
    'net.ipv6.conf.all.disable_ipv6 '
    'net.ipv6.conf.default.disable_ipv6',
    capture_output=True
  )
  if res.stdout != b'1\n1\n':
    print("""\
warning: IPv6 is enabled

PIA currently does not support IPv6. To make sure that your VPN
connection does not leak, it is best to disabled IPv6 altogether:

sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 \
net.ipv6.conf.default.disable_ipv6=1
""")

class ConfigValidator(cerberus.Validator):
  def _validate_isusername(self, isusername, field, value):
    "{'type': 'boolean'}"
    if isusername and re.match(r'^p\d{7}$', value) == None:
      self._error(field, 'Must have format p#######')
  def _validate_isregion(self, isregion, field, value):
    "{'type': 'boolean'}"
    if isregion and value != '' and not value in valid_regions:
      self._error(
        field, 'Must be one of %s' % ', '.join(list(valid_regions))
      )
  def _validate_isprotocol(self, isprotocol, field, value):
    "{'type': 'boolean'}"
    if isprotocol and not value in valid_protocols:
      self._error(
        field, 'Must be one of %s' % ', '.join(list(valid_protocols))
      )
  def _validate_istcpudp(self, istcpudp, field, value):
    "{'type': 'boolean'}"
    if istcpudp and not value in {'tcp', 'udp'}:
      self._error(field, 'Must be one of tcp, udp')
  def _validate_isstandardstrong(self, isstandardstrong, field, value):
    "{'type': 'boolean'}"
    if isstandardstrong and not value in {'standard', 'strong'}:
      self._error(field, 'Must be one of standard, strong')
  def _validate_isip(self, isip, field, value):
    "{'type': 'boolean'}"
    if isip:
      try:
        ipaddress.ip_address(value)
      except ValueError as e:
        self._error(field, 'Must be IP address')
  def _validate_ishostname(self, ishostname, field, value):
    "{'type': 'boolean'}"
    if ishostname and is_valid_hostname(value) == False:
      self._error(field, 'Must be a server name')
  def _validate_iscountry(self, iscountry, field, value):
    "{'type': 'boolean'}"
    # validator is also called on default value ''
    if iscountry and re.match(r'^[A-Z]{2}|$', value) == None:
      self._error(field,
        f'Must be country code with 2 uppercase letters')

# https://stackoverflow.com/a/2532344/10440128
def is_valid_hostname(hostname):
  if len(hostname) > 255:
    return False
  if hostname[-1] == '.':
    hostname = hostname[:-1] # strip last dot
  allowed = re.compile(r'(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
  return all(allowed.match(x) for x in hostname.split('.'))

config_schema = {
  'username': {'type': 'string', 'required': True, 'isusername': True},
  'password': {'type': 'string', 'required': True, 'minlength': 8},
  'protocol': {'type': 'string', 'default': 'wireguard', 'isprotocol': True},
  'openvpn': {'type': 'dict', 'default': dict(), 'schema': {
    'protocol': {'type': 'string', 'istcpudp': True},
    'encryption': {'type': 'string', 'isstandardstrong': True},
  }},
  'portforwarding': {'type': 'boolean', 'default': False},
  'setdns': {'type': 'boolean', 'default': True},
  'usesudo': {'type': 'boolean', 'default': True},
  'server': {'type': 'dict', 'default': dict(), 'schema': {
    'ip': {'type': 'string', 'isip': True},
    'name': {'type': 'string', 'ishostname': True},
    #'country': {'type': 'string', 'iscountry': True, 'default': ''},
  }},
  'region': {'type': 'string', 'default': '', 'isregion': True},
  'green_regions': {'type': 'boolean', 'default': False},
  'yellow_regions': {'type': 'boolean', 'default': False},
  'disableipv6': {'type': 'boolean', 'default': True},
  'tokenfile': {'type': 'string', 'default': '/opt/piavpn-manual/token'},
  'maxlatency': {'type': 'integer', 'default': 200},
  'geoipdb': {'type': 'string', 'default': '/usr/share/GeoIP/GeoIP.dat'},
}

def config_not_found():
  # todo auto-generate from schema?
  die(f'''\
config file not found
default location is /etc/piavpn.yaml
to use a different config file, use `{script_name} --config /path/to/piavpn.yaml`
sample config:

username: p1234567
password: your_password_here

# optional fields
#protocol: wireguard
#portforwarding: false
#setdns: true # Using third party DNS could allow DNS monitoring
#disableipv6: true # IPv6 connections might compromise security
#usesudo: true
#green_regions: True # Show only green regions
#yellow_regions: True # Show only green and yellow regions 
#maxlatency: 200 # milliseconds
#tokenfile: /opt/piavpn-manual/token
#server: # see `{script_name} --servers`
#  ip: 1.2.3.4
#  name: some-server
#region: spain # see `{script_name} --regions`
#openvpn:
#  protocol: tcp
#  encryption: standard
#geoipdb: /usr/share/GeoIP/GeoIP.dat
''')

# todo dynamic?
#print(repr(sorted([r.id for r in full_server_list.regions])))
valid_regions = {
  'ad', 'ae', 'al', 'ar', 'aus', 'aus_melbourne', 'aus_perth', 'austria',
  'ba', 'bahamas', 'bangladesh', 'belgium', 'br', 'ca', 'ca_ontario',
  'ca_toronto', 'ca_vancouver', 'cambodia', 'china', 'cyprus', 'czech',
  'de-frankfurt', 'de_berlin', 'denmark', 'dz', 'ee', 'egypt', 'fi',
  'france', 'georgia', 'gr', 'greenland', 'hk', 'hungary', 'in', 'ireland',
  'is', 'israel', 'italy', 'japan', 'kazakhstan', 'liechtenstein', 'lt',
  'lu', 'lv', 'macau', 'malta', 'man', 'md', 'mexico', 'mk', 'monaco',
  'mongolia', 'montenegro', 'morocco', 'nigeria', 'nl_amsterdam', 'no',
  'nz', 'panama', 'philippines', 'poland', 'pt', 'qatar', 'ro', 'rs',
  'saudiarabia', 'sg', 'sk', 'sofia', 'spain', 'srilanka', 'sweden',
  'swiss', 'taiwan', 'tr', 'ua', 'uk', 'uk_2', 'uk_manchester',
  'uk_southampton', 'us-newjersey', 'us3', 'us_atlanta', 'us_california',
  'us_chicago', 'us_denver', 'us_florida', 'us_houston', 'us_las_vegas',
  'us_new_york_city', 'us_seattle', 'us_silicon_valley', 'us_south_west',
  'us_washington_dc', 'venezuela', 'vietnam', 'yerevan', 'za',
}

# copyright laws by country
#
# green_regions = Downloading allowed (for personal use)
# yellow_regions = Download Fines (not enforced)
# red_regions = Download fines (enforced)
# black_regions = unknown copyright laws
#
# https://vpnoverview.com/privacy/downloading/download-fines/
# https://www.vpnmentor.com/blog/torrents-illegal-update-country/
# https://vpnpro.com/blog/is-torrenting-illegal/

green_regions = {
  "poland", # Poland
  "spain", # Spain, Madrid
  "es-valencia", # Spain
  "swiss", # Switzerland
}

yellow_regions = {
  "ar", # Argentina
  "aus", # Australia, Sydney
  "au_australia-so", # Australia, Streaming Optimized
  "aus_melbourne", # Australia, Melbourne
  "aus_perth", # Australia, Perth
  "br", # Brazil
  "ca_ontario", # Canada
  "ca_toronto", # Canada
  "ca_vancouver", # Canada
  "china", # China
  "bogota", # Colombia
  "czech", # Czech Republic
  "denmark", # Denmark
  "denmark_2", # Denmark, Streaming Optimized
  "egypt", # Egypt
  "gr", # Greece
  #"Iran",
  "israel", # Israel
  "italy", # Italy, Milano
  "italy_2", # Italy, Streaming Optimized
  "lv", # Latvia
  "mexico", # Mexico
  "nl_amsterdam", # Netherlands
  "philippines", # Philippines
  "pt", # Portugal
  "ro", # Romania
  #'rs', # Russia
  "sg", # Singapore
  "sk", # Slovakia
  "slovenia", # Slovenia
  "za", # South Africa
  #"Uruguay",
}

red_regions = {
  "belgium", # Belgium
  "fi", # Finland, Helsinki
  "fi_2", # FI Streaming Optimized
  "france", # France
  "de-frankfurt", # Germany
  "de_berlin", # Germany
  "in", # India
  "japan_2", # Japan, Streaming Optimized
  # Malaysia
  # New Zealand
  "ae", # United Arab Emirates
  "uk", # United Kingdom, London
  "uk_2", # United Kingdom, Streaming Optimized
  "uk_manchester", # United Kingdom, Manchester
  # United States
  'us-newjersey', 'us3', 'us_atlanta', 'us_california',
  'us_chicago', 'us_denver', 'us_florida', 'us_houston', 'us_las_vegas',
  'us_new_york_city', 'us_seattle', 'us_silicon_valley', 'us_south_west',
  'us_washington_dc',
}

black_regions = {
  "panama", # 
  "venezuela", # 
  "sofia", # Bulgaria
  "hungary", # 
  "kazakhstan", # 
  "nigeria", # 
  "al", # Albania
  "lu", # Luxembourg
  "montenegro", # 
  "zagreb", # Croatia
  "dz", # Algeria
  "lt", # Lithuania
  "morocco", # 
  "qatar", # 
  "ad", # Andorra
  "hk", # Hong Kong
  "mk", # North Macedonia
  "liechtenstein", # 
  "taiwan", # 
  "malta", # 
  "vietnam", # 
  "ba", # Bosnia and Herzegovina
  "srilanka", # Sri Lanka
  "sanjose", # Costa Rica
  "mongolia", # 
  "sweden_2", # SE Streaming Optimized
  "bahamas", # 
  "no", # Norway
  "saudiarabia", # Saudi Arabia
  "jakarta", # Indonesia
  "bangladesh", # 
  "ua", # Ukraine
  "monaco", # 
  "yerevan", # Armenia
  "ireland", # 
  "cyprus", # 
  "sweden", # SE Stockholm
  "ee", # Estonia
  "greenland", # 
  "man", # Isle of Man
  "macau", # Macao
  "cambodia", # 
  "rs", # Serbia
}

valid_protocols = {'wireguard', 'openvpn'}



if __name__ == '__main__':
  main()
# else: allow to use functions from other script
