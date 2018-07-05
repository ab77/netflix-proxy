#!/usr/bin/env python

import sys
import os
import time
import inspect
import traceback
import argparse
import json
import uuid

from pprint import pprint
from subprocess import Popen, PIPE
from sys import argv, stdout, stderr
from socket import socket, gethostbyname
from functools import wraps

try:
    import requests
except ImportError:
    stderr.write('ERROR: Python module "requests" not found, please run "pip install requests".\n')
    exit(1)

try:
    import dns.resolver
except ImportError:
    stderr.write('ERROR: Python module "dnspython" not found, please run "pip install dnspython".\n')
    exit(1)
    
try:
    from termcolor import colored
except ImportError:
    stderr.write('ERROR: Python module "termcolor" not found, please run "pip install termcolor".\n')
    exit(1)

try:
    from OpenSSL.SSL import (OP_NO_SSLv3, TLSv1_2_METHOD, Context, Connection)
except ImportError:
    stderr.write('ERROR: Python module "OpenSSL" not found, please run "pip install pyopenssl".\n')
    exit(1)

from settings import *


def retry(ExceptionToCheck, tries=DEFAULT_TRIES, delay=DEFAULT_DELAY, backoff=DEFAULT_BACKOFF, cdata=None):
    '''Retry calling the decorated function using an exponential backoff.

    http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    original from: http://wiki.python.org/moin/PythonDecoratorLibrary#Retry

    :param ExceptionToCheck: the exception to check. may be a tuple of
        exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
        each retry
    :type backoff: int
    :param logger: logger to use. If None, print
    :type logger: logging.Logger instance
    '''
    def deco_retry(f):
        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 0:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck, e:
                    logger(message='%s, retrying in %d seconds (mtries=%d): %s' % (repr(e), mdelay, mtries, str(cdata)))
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)
        return f_retry  # true decorator
    return deco_retry


def logger(message=None):
    print '%s\n' % repr(message)


def get_public_ip():
    resolver = dns.resolver.Resolver()
    resolver.nameservers=[gethostbyname('resolver1.opendns.com')]
    return str(resolver.query('myip.opendns.com', 'A').rrset[0])


def get_regions(s):
    response = s.get('%s/regions' % BASE_API_URL)
    d = json.loads(response.text)
    slugs = []
    for region in d['regions']:
        slugs.append(region['slug'])
            
    return slugs


def args():   
    parser = argparse.ArgumentParser()
    sp = parser.add_subparsers(help='version %s' % VERSION)    
    digitalocean = sp.add_parser('digitalocean')
    digitalocean.add_argument('provider', action='store_const', const='digitalocean', help=argparse.SUPPRESS)
    digitalocean.add_argument('--api_token', type=str, required=True, help='DigitalOcean API v2 secret token')
    digitalocean.add_argument('--client_ip', type=str, required=False, default=get_public_ip(), help='client IP to secure Droplet')
    digitalocean.add_argument('--fingerprint', nargs='+', type=str, required=False, default=DEFAULT_FINGERPRINT, help='SSH key fingerprint')
    digitalocean.add_argument('--region', type=str, required=False, default=DEFAULT_REGION_SLUG, help='region to deploy into; use --list_regions for a list')
    digitalocean.add_argument('--branch', type=str, required=False, default=DEFAULT_BRANCH, help='netflix-proxy branch to deploy (default: %s)' % DEFAULT_BRANCH)
    digitalocean.add_argument('--create', action='store_true', required=False, help='Create droplet')
    digitalocean.add_argument('--destroy', action='store_true', required=False, help='Destroy droplet')
    digitalocean.add_argument('--list_regions', action='store_true', required=False, help='list all available regions')
    digitalocean.add_argument('--name', type=str, required=False, help='Droplet name')
    args = parser.parse_args()
    return args


def create_droplet(s, name, cip, fps, region, branch=DEFAULT_BRANCH):
    user_data = '''#cloud-config

runcmd:
  - git clone -b {} https://github.com/ab77/netflix-proxy\
      && cd netflix-proxy\
      && ./build.sh -c {}'''.format(branch, cip)
    
    json_data = {'name': name,
                 'region': region,
                 'size': DEFAULT_MEMORY_SIZE_SLUG,
                 'vcpus': DEFAULT_VCPUS,
                 'disk': DEFAULT_DISK_SIZE,
                 'image': DOCKER_IMAGE_SLUG,
                 'ssh_keys': fps,
                 'backups': False,
                 'ipv6': False,
                 'private_networking': False,
                 'user_data': user_data}
    
    s.headers.update({'Content-Type': 'application/json'})
    post_body = json.dumps(json_data)
    response = s.post('%s/droplets' % BASE_API_URL, data=post_body)
    d = json.loads(response.text)
    pprint(d)

    @retry(AssertionError, cdata='method=%s()' % inspect.stack()[0][3])
    def wait_for_vm_provisioning_completion_retry(action_url):
        response = s.get(action_url)
        d = json.loads(response.text)
        if 'completed' in d['action']['status']:
            print colored(d['action']['status'], 'green')
            assert True
            return d
        else:
            print colored(d['action']['status'], 'red')
            assert False
            return None
        
    if 'links' not in d:
        return False
    else:
        return wait_for_vm_provisioning_completion_retry(d['links']['actions'][0]['href'])


def destroy_droplet(s, droplet_id):

    @retry(AssertionError)
    def wait_for_vm_deletion_completion_retry(s, droplet_id):
        response = s.delete('%s/droplets/%d' % (BASE_API_URL,
                                                droplet_id))
        if response.__dict__['status_code'] == 204:
            print colored('DELETE /droplets/%d status code %d' % (droplet_id, response.__dict__['status_code']), 'green')
            assert True
            return response.__dict__
        else:
            print colored('DELETE /droplets/%d status code %d' % (droplet_id, response.__dict__['status_code']), 'red')
            assert False
            return None

    return wait_for_vm_deletion_completion_retry(s, droplet_id)


def get_droplet_id_by_name(s, name):
    response = s.get('%s/droplets' % BASE_API_URL)
    d = json.loads(response.text)
    droplet_id = None
    for droplet in d['droplets']:
        if name in droplet['name']:
            droplet_id = droplet['id']
            
    return droplet_id


def get_droplet_ip_by_name(s, name):
    response = s.get('%s/droplets' % BASE_API_URL)
    d = json.loads(response.text)
    droplet_ip = None
    for droplet in d['droplets']:
        if name in droplet['name']:
            droplet_ip = droplet['networks']['v4'][0]['ip_address']
            
    return droplet_ip


def get_droplet_name_by_ip(s, ip):
    response = s.get('%s/droplets' % BASE_API_URL)
    d = json.loads(response.text)
    droplet_name = None
    for droplet in d['droplets']:
        droplet_ip = droplet['networks']['v4'][0]['ip_address']
        if ip in droplet_ip:
            droplet_name = droplet['name']
            
    return droplet_name


def ssh_run_command(ip, command):
    result = None
    ssh = Popen(['ssh', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no',
                 '-i', 'id_rsa.travis', 'root@%s' % ip, command],
                shell=False, stdout=PIPE, stderr=PIPE)
    (stdout, stderr) = ssh.communicate()
    print colored('%s: pid = %d, stdout = %s, stderr = %s, rc = %d' % (inspect.stack()[0][3],
                                                                       ssh.pid,
                                                                       stdout.splitlines(),
                                                                       stderr.splitlines(),
                                                                       ssh.returncode), 'grey')
    return dict({'stdout': stdout.splitlines(),
                 'stderr': stderr.splitlines(),
                 'rc': ssh.returncode,
                 'pid': ssh.pid})


@retry(AssertionError, cdata='method=%s()' % inspect.stack()[0][3])
def docker_test_retry(ip):
    stdout = ssh_run_command(ip, 'docker ps')['stdout']
    # https://docs.docker.com/reference/commandline/ps/
    if len(stdout) < 5: # quick and dirty check (5 lines of output = header + containers), needs improvement..
        print colored('%s: stdout = %s, len(stdout) = %d' % (inspect.stack()[0][3],
                                                             stdout,
                                                             len(stdout)), 'red')
        assert False
        return False
    else:
        print colored('%s: stdout = %s, len(stdout) = %d' % (inspect.stack()[0][3],
                                                             stdout,
                                                             len(stdout)), 'green')
        assert True
        return True


def docker_test(ip):
    return docker_test_retry(ip)


def netflix_proxy_test(ip):

    @retry(AssertionError, cdata='method=%s()' % inspect.stack()[0][3])
    def netflix_proxy_test_retry(ip):
        ssh_run_command(ip, 'tail /var/log/cloud-init-output.log')
        rc = ssh_run_command(ip, "grep -E 'Change your DNS to ([0-9]{1,3}[\.]){3}[0-9]{1,3} and start watching Netflix out of region\.' /var/log/cloud-init-output.log")['rc']
        if rc > 0:
            print colored('%s: SSH return code = %s' % (inspect.stack()[0][3], rc), 'red')
            assert False
            return None
        else:
            print colored('%s: SSH return code = %s' % (inspect.stack()[0][3], rc), 'green')
            assert True
            return rc
            
    return netflix_proxy_test_retry(ip)


def netflix_openssl_test(ip=None, port=443, hostname=DEFAULT_NFLX_HOST):
    """
    Connect to an SNI-enabled server and request a specific hostname
    """

    @retry(Exception, cdata='method=%s()' % inspect.stack()[0][3])
    def netflix_openssl_test_retry(ip):
        client = socket()
        
        print 'Connecting...',
        stdout.flush()
        client.connect((ip, port))
        print 'connected', client.getpeername()

        context_ssl = Context(TLSv1_2_METHOD)
        context_ssl.set_options(OP_NO_SSLv3)
        client_ssl = Connection(context_ssl, client)
        client_ssl.set_connect_state()
        client_ssl.set_tlsext_host_name(hostname)
        client_ssl.do_handshake()
        cert = client_ssl.get_peer_certificate().get_subject()
        cn = [comp for comp in cert.get_components() if comp[0] in ['CN']]
        client_ssl.close()
        print cn
        if hostname in cn[0][1]:
            return True
        else:
            return False

    if not ip: ip = get_public_ip()
    return netflix_openssl_test_retry(ip)


def netflix_test(ip=None, host=DEFAULT_NFLX_HOST):

    @retry(Exception, tries=3, delay=10, backoff=2, cdata='method=%s()' % inspect.stack()[0][3])
    def netflix_openssl_test_retry(ip):
        status_code = requests.get('http://%s' % ip, headers={'Host': host}, timeout=10).status_code
        print '%s: status_code=%s' % (host, status_code)
        if not status_code == 200:
            return False
        else:
            return True

    if not ip: ip = get_public_ip()
    return netflix_openssl_test_retry(ip)


def reboot_test(ip):
    stdout = ssh_run_command(ip, 'sudo reboot')['stdout']
    print colored('%s: stdout = %s' % (inspect.stack()[0][3], stdout), 'grey')
    time.sleep(DEFAULT_SLEEP)
    return docker_test_retry(ip)


def set_sysdns(ips):
    # quick hack, clobbers /etc/resolv.conf
    ns = None
    if isinstance(ips, unicode):
        ns = 'nameserver %s' % ips
    elif isinstance(ips, list):
        for i in xrange(0, len(ips)):
            ips[i] = 'nameserver %s'% ips[i]            
        ns = '\n'.join(ips)
    if ns: return os.system('printf "%s\n" | sudo tee /etc/resolv.conf' % ns)


def get_sysdns():
    return dns.resolver.Resolver().nameservers


if __name__ == '__main__':
    arg = args()
    if arg.api_token:
        if not arg.name:
            name = str(uuid.uuid4())
        else:
            name = arg.name
            
        droplet_id = None
        s = requests.Session()
        if DEFAULT_PROXY:
            s.verify = False
            s.proxies = {'http' : 'http://%s' % DEFAULT_PROXY,
                         'https': 'https://%s' % DEFAULT_PROXY}
        s.headers.update({'Authorization': 'Bearer %s' % arg.api_token})
    
        if arg.list_regions:
            pprint(get_regions(s))
            exit(0)

        if arg.create:
            try:
                print colored('client_ip={}'.format(arg.client_ip), 'cyan')
                print colored('Creating Droplet {}...'.format(name), 'yellow')
                d = create_droplet(s, name, arg.client_ip, arg.fingerprint, arg.region, branch=arg.branch)                
                pprint(d)
                
                droplet_ip = get_droplet_ip_by_name(s, name)
                print colored('Droplet ipaddr = %s...' % droplet_ip, 'cyan')

                print colored('Checking running Docker containers on Droplet with name = %s, ipaddr = %s...' % (name, droplet_ip), 'yellow')
                result = docker_test(droplet_ip)
                if not result: exit(1)
                
                print colored('Testing netflix-proxy on Droplet with name = %s, ipaddr = %s...' % (name, droplet_ip), 'yellow')
                rc = netflix_proxy_test(droplet_ip)
                if rc > 0: exit(rc)
        
                print colored('Rebooting Droplet with name = %s, ipaddr = %s...' % (name, droplet_ip), 'yellow')
                result = reboot_test(droplet_ip)
                if not result: exit(1)

                print colored('SNIProxy remote test (OpenSSL) on Droplet with name = %s, ipaddr = %s...' % (name, droplet_ip), 'yellow')
                rc = netflix_openssl_test(ip=droplet_ip)
                if not rc: exit(1)

                print colored('SNIProxy remote test (HTTP/S) on Droplet with name = %s, ipaddr = %s...' % (name, droplet_ip), 'yellow')
                rc = netflix_test(ip=droplet_ip)
                if not rc: exit(1)

                print colored('get_sysdns(): %s' % get_sysdns(), 'grey')
                print colored('Setting system resolver to nameserver = %s...' % droplet_ip, 'yellow')
                rc = set_sysdns(droplet_ip)
                if rc > 0: exit(1)

                print colored('get_sysdns(): %s' % get_sysdns(), 'cyan')

                print colored('Tested, OK..', 'green')
                
            except Exception:
                print colored(traceback.print_exc(), 'red')
                exit(1)
                
            finally:
                if arg.destroy:
                    droplet_id = get_droplet_id_by_name(s, name)
                    if droplet_id:
                        print colored('Destroying Droplet name = %s, id = %s...' % (name, droplet_id), 'yellow')
                        d = destroy_droplet(s, droplet_id)
                        pprint(d)
                        
        elif arg.destroy and arg.name and not arg.create:
            droplet_id = get_droplet_id_by_name(s, arg.name)
            print colored('Destroying Droplet name = %s id = %s...\n' % (arg.name,
                                                                         droplet_id), 'red')
            time.sleep(DEFAULT_SLEEP)
            d = destroy_droplet(s, droplet_id)
            pprint(d)

        else:
            print('No action specified: [--create] [--destroy] [--list_regions]')
