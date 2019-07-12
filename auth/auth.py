#!/usr/bin/env python

# -*- coding: utf-8 -*-

"""auth.py: basic web front-end to auth/de-auth ipaddrs using iptables.
author: anton@belodedenko.me
"""

from subprocess import Popen, PIPE
from collections import defaultdict
import datetime, traceback, sys, socket
from settings import *

try:
    import web
except ImportError:
    sys.stderr.write('ERROR: Python module "web.py" not found, please run "pip install web.py".\n')
    sys.exit(1)
    
try:
    from passlib.hash import pbkdf2_sha256
except ImportError:
    sys.stderr.write('ERROR: Python module "passlib" not found, please run "pip install passlib".\n')
    sys.exit(1)

try:
    from dns import (resolver, reversename)
except ImportError:
    sys.stderr.write('ERROR: Python module "dnspython" not found, please run "pip install dnspython".\n')
    sys.exit(1)


def run_ipt_cmd(ipaddr, op):
    iface = get_iface()
    web.debug('DEBUG: public iface=%s ipaddr=%s' % (iface, ipaddr))
    ipt_cmd = 'iptables -t nat -%s PREROUTING -s %s/32 -i %s -j ACCEPT -v && iptables-save > /etc/iptables/rules.v4' % (op, ipaddr, iface)
    web.debug('DEBUG: ipaddr=%s, op=%s, ipt_cmd=%s' % (ipaddr, op, ipt_cmd))
    p = Popen(ipt_cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    output, err = p.communicate()
    rc = p.returncode
    return rc, err, output


def run_ipt6_cmd(ipaddr, op):
    iface = get_iface()
    web.debug('DEBUG: public iface=%s ipaddr=%s' % (iface, ipaddr))
    ipt_cmd = 'ip6tables -t nat -%s PREROUTING -s %s/128 -i %s -j ACCEPT -v && ip6tables-save > /etc/iptables/rules.v6' % (op, ipaddr, iface)
    web.debug('DEBUG: ipaddr=%s, op=%s, ipt_cmd=%s' % (ipaddr, op, ipt_cmd))
    p = Popen(ipt_cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    output, err = p.communicate()
    rc = p.returncode
    return rc, err, output


def get_client_public_ip():
    return web.ctx.env.get('HTTP_X_FORWARDED_FOR') or web.ctx.get('ip', None)


def get_iface():
    cmd = "ip route | grep default | awk '{print $5}' | head -n 1"
    web.debug('DEBUG: getting public iface name cmd=%s' % cmd)
    p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    output, err = p.communicate()
    rc = p.returncode
    web.debug('DEBUG: get_iface()=%s' % [rc, err, output])
    if rc == 0:
        try:
            iface = output.rstrip().decode()
        except:
            iface = output.rstrip()
    else:
        iface = 'eth0'
        web.debug('WARNING: get_iface() failed, guessing iface=%s' % iface)
        
    return iface


def get_server_iface_ip():
    iface = get_iface()
    cmd = """ip addr show dev %s | \
      grep inet | \
      grep -v inet6 | \
      awk '{print $2}' | \
      grep -Po '[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+\.[0-9]{1,3}+(?=\/)'""" % iface
    
    web.debug('DEBUG: getting ipaddr from iface=%s cmd=%s' % (iface, cmd))
    p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    output, err = p.communicate()
    rc = p.returncode
    web.debug('DEBUG: get_server_iface_ip()=%s' % [rc, err, output])
    if rc == 0:
        try:
            ipaddr = output[0].rstrip().decode()
        except:
            ipaddr = output[0].rstrip()
    else:
        ipaddr = web.ctx.env['SERVER_NAME']
        web.debug('WARNING: get_server_iface_ip() failed, guessing ipaddr=%s' % ipaddr)
        
    return ipaddr


def get_server_external_ip():
    try:
        reslvr = resolver.Resolver()
        reslvr.nameservers=[socket.gethostbyname('resolver1.opendns.com')]
        return str(reslvr.query('myip.opendns.com', 'A').rrset[0]).lower()
    
    except Exception as e:
        web.debug('DEBUG: get_server_external_ip(): %s' % repr(e))
        return get_server_iface_ip()


def get_server_public_fqdn():
    try:
        reslvr = resolver.Resolver()
        ipaddr = reversename.from_address(get_server_external_ip())
        return str(reslvr.query(ipaddr, 'PTR')[0]).rstrip('.').lower()
    
    except Exception as e:
        web.debug('DEBUG: get_server_public_fqdn(): %s' % repr(e))
        return ipaddr
    

def get_http_host():
    return web.ctx.environ['HTTP_HOST'].split(':')[0] or 'localhost'


def is_redirected():
    ipaddr = get_server_external_ip()
    fqdn = get_server_public_fqdn()
    http_host = get_http_host()
    if http_host == ipaddr or http_host == fqdn:
        return False
    else:
        return True
    

def csrf_token():
    if not 'csrf_token' in session:
        from uuid import uuid4
        session.csrf_token = uuid4().hex
    return session.csrf_token


def csrf_protected(f):
    def decorated(*args, **kwargs):
        inp = web.input()
        if not ('csrf_token' in inp and inp.csrf_token == session.pop('csrf_token', None)):
            raise web.HTTPError(
                "400 Bad request",
                {'content-type':'text/html'},
                """Cross-site request forgery (CSRF) attempt (or stale browser form). <a href="">Back to the form</a>.""")
        return f(*args, **kwargs)
    return decorated


def validate_user(username,password):
    try:
        results = db.query("SELECT * FROM users WHERE username=$username ORDER BY ROWID ASC LIMIT 1",
                           vars={'username': username})
        user = results[0]

        try:
            valid_hash = pbkdf2_sha256.verify(password, user.password)
        except ValueError as e:
            web.debug('%s user=%s' % (str(e), user.username))
            valid_hash = None
            pass
            
        date_now = datetime.datetime.now()
        date_expires = datetime.datetime.combine(user.expires, datetime.time.min)
        if date_now <= date_expires:
            if valid_hash:
                web.debug('login_success_hash: user=%s' % user.username)
                return user
            else:
                web.debug('login_failed_hash: incorrect password user=%s, fallback to plaintext' % user.username)
            
                if password == user.password:
                    web.debug('login_success_plaintext: user=%s' % user.username)
                    return user
                else:
                    web.debug('login_failed_plaintext: incorrect password user=%s' % user.username)
                    return None
        else:
            web.debug('login_failed: expired account user=%s' % user.username)
            return None
    
    except IndexError as e:
        web.debug('login_failed: not found user=%s' % username)
        return None
        

def get_ipaddrs():
    results = db.query('SELECT * FROM ipaddrs WHERE user_id=$user_id',
                       vars={'user_id': session.user['ID']})
    
    ipaddrs = [ip['ipaddr'] for ip in results]
    session.auth_ip_count = len(ipaddrs)
    ip = get_client_public_ip()
    if ip in ipaddrs:
        session.already_authorized = True
    else:
        session.already_authorized = False
    return ipaddrs


def get_form(name='add'):
    if FORM_INPUTS_HIDDEN:
        ipaddr_input = web.form.Hidden('ipaddr')
    else:
        ipaddr_input = web.form.Textbox('ipaddr')
    if session.user['privilege'] == 1:
        if name == 'add':
            frm = web.form.Form(ipaddr_input,
                                web.form.Button('Add', type='submit', value='submit', id='submit'))
        if name == 'delete':
            frm = web.form.Form(ipaddr_input,
                                web.form.Button('Delete', type='submit', value='submit', id='submit'))

        frm.ipaddr.value = get_client_public_ip()        
        session.auth_ip_count = 0
        session.already_authorized = False
        frm.title = 'admin'
    else:
        ipaddrs = get_ipaddrs()
        if name == 'add':
            frm = web.form.Form(web.form.Dropdown('ipaddr', []),
                                web.form.Button('Add', type='submit', value='add', id='add'))

            frm.ipaddr.args = [get_client_public_ip()]
            frm.title = 'add'
        if name == 'delete':
            frm = web.form.Form(web.form.Dropdown('ipaddr', []),
                                web.form.Button('Delete', type='submit', value='delete', id='delete'))

            frm.ipaddr.args = get_ipaddrs()
            frm.title = 'delete'
            if not ipaddrs:
                frm = web.form.Form()
                frm.title = 'delete'             
    return frm


def get_redirect_page():
    content = web.form.Form()
    content.title = 'Redirect to Google'
    content.redirect_url = 'http://google.com/'
    return content
                

# Set a custom 404 not found error message
def notfound():
  web.ctx.status = '404 Not Found'
  return web.notfound(str(render.__404()))


# Set a custom internal error message
def internalerror():
  web.ctx.status = '500 Internal Server Error'
  return web.internalerror(str(render.__500()))


def flash(group, message):
    session.flash[group].append(message)


def flash_messages(group=None):
    if not hasattr(web.ctx, 'flash'):
        web.ctx.flash = session.flash
        session.flash = defaultdict(list)
    if group:
        return web.ctx.flash.get(group, [])
    else:
        return web.ctx.flash


web.config.debug = DEBUG
web.config.session_parameters['cookie_name'] = 'netflix-proxy-admin'

urls = (
    r'/login', 'Login',
    r'/logout', 'Logout',
    r'/add', 'Add',
    r'/autoadd', 'AutoAdd',
    r'/delete', 'Delete',
    r'/ddns', 'DDNSIndex',
    r'/ddns/add', 'DDNSAdd',
    r'/ddns/delete', 'DDNSDelete',
    r'.*', 'Index'
)

app = web.application(urls, globals())

db = web.database(dbn='sqlite', db=SQLITE_DB)

# Setup the application's error handlers
app.internalerror = internalerror
app.notfound = notfound

# Allow session to be reloadable in development mode.
if web.config.get('_session') is None:
    session = web.session.Session(app, web.session.DiskStore('sessions'),
                                  initializer={'flash': defaultdict(list)})

    web.config._session = session
else:
    session = web.config._session

render = web.template.render('templates/',
                             base='base',
                             cache=False)

t_globals = web.template.Template.globals
t_globals['datestr'] = web.datestr
t_globals['app_version'] = lambda: VERSION + ' - ' + VERSION
t_globals['flash_messages'] = flash_messages
t_globals['render'] = lambda t, *args: render._template(t)(*args)
t_globals['csrf_token'] = csrf_token
t_globals['context'] = session

class Index:

    def GET(self):
        ipaddr = get_client_public_ip()
        is_ipv4 = web.net.validipaddr(ipaddr)
        is_ipv6 = web.net.validip6addr(ipaddr)
        
        if AUTO_AUTH:            
            if ipaddr:
                web.debug('AUTO_AUTH: %s' % ipaddr)
                if is_ipv4: result = run_ipt_cmd(ipaddr, 'I')
                if is_ipv6: result = run_ipt6_cmd(ipaddr, 'I')
                web.debug('iptables_update: %s' % [result])
                if result[0] == 0: 
                    flash('success', 'automatically authorized %s' % ipaddr)
                    return render.redirect(get_redirect_page())
                else:
                    flash('error', 'unable to automatically authorize %s' % ipaddr)
                    raise web.seeother('/add')
            else:
                flash('error', 'something went wrong, please login to authorize')
                raise web.seeother('/')
        else:
            try:
                if session.user:
                    ipaddrs = get_ipaddrs()
                    if len(ipaddrs) == 0:
                        return web.seeother('/add')
                    return render.index(ipaddrs)
            except Exception as e:
                web.debug(traceback.print_exc())
                raise web.seeother('/login')
            

class Login:

    loginform = web.form.Form(web.form.Textbox('username',
                                               web.form.notnull,
                                               web.form.regexp('^[a-zA-Z0-9]+$', 'Alpha-numeric characters only (maximum %s)' % USERNAME_MAX_LEN),
                                               web.form.Validator('Not more than %s characters.' % USERNAME_MAX_LEN, lambda x: len(x)<USERNAME_MAX_LEN)),
                              web.form.Password('password',
                                                web.form.notnull,
                                                web.form.regexp('[ -~]', 'Printable characters only (maximum %s)' % PASSWORD_MAX_LEN),
                                                web.form.Validator('Not more than %s characters.' % PASSWORD_MAX_LEN, lambda x: len(x)<PASSWORD_MAX_LEN)))

    def get_login_form(self):
        login_form = Login.loginform()
        login_form.title = 'login'
        return login_form


    def GET(self):
        ipaddr = get_client_public_ip()
        web.config.session_parameters['cookie_domain'] = web.ctx.environ['HTTP_HOST']
        try:
            if session.user:
                raise web.seeother('/')
            else:
                flash('success', 'welcome, please login to authorize %s' % ipaddr)                
                return render.login(self.get_login_form())
            
        except Exception as e:
            web.debug(traceback.print_exc())
            flash('success', 'welcome, please login to authorize %s' % ipaddr)                
            return render.login(self.get_login_form())


    @csrf_protected # Verify this is not CSRF, or fail
    def POST(self):
        login_form = self.get_login_form()
        if not login_form.validates():
            flash('error', 'form validation failed')
            return render.login(login_form)
        username = login_form['username'].value
        password = login_form['password'].value
        user = validate_user(username,password)
        if user:
            session.user = user
            web.debug(web.config.session_parameters)
            flash('success', """you are now logged in, "Add" to authorize %s""" % get_client_public_ip())
            raise web.seeother('/')
        else:
            session.user = None
            flash('error', 'login failed for user %s' % username)
            raise web.seeother('/login')
        return render.login(login_form)


class Logout:
    
    def GET(self):
        session.user = None
        session.already_authorized = None
        session.auth_ip_count = None
        session.kill()
        raise web.seeother('/login')

class AutoAdd:

    def GET(self):
        try:
            params = web.input(ip=get_client_public_ip())
            user = validate_user(params.username,params.password)
            if user is None: return 'Error: login'

            ipadr = params.ip
            is_ipv4 = web.net.validipaddr(ipadr)
            is_ipv6 = web.net.validip6addr(ipadr)
            if is_ipv4 == False and is_ipv6 == False:
                return 'Error: IP not in right form'

            # userid = int(user.ID)
            userid = user.ID
            results = db.query(
                'SELECT * FROM ipaddrs WHERE user_id=$user_id',
                vars={
                    'user_id': userid
                }
            )

            ipaddrs = [ip['ipaddr'] for ip in results]
            if ipadr in ipaddrs: return 'Error: already authorized.'

            db_result = db.insert('ipaddrs', user_id=userid, ipaddr=ipadr)
            web.debug('db_update: %s' % [db_result])

            if is_ipv4: result = run_ipt_cmd(ipadr, 'I')
            if is_ipv6: result = run_ipt6_cmd(ipadr, 'I')
            web.debug('iptables_update: %s' % [result])
            return 'OK'
        except Exception as e:
            web.debug(traceback.print_exc())
            return user.ID


class Add:
    
    def GET(self):
        try:
            if session.user:
                return render.form(get_form())
            else:
                raise web.seeother('/login')

        except Exception as e:
            web.debug(traceback.print_exc())
            raise web.seeother('/login')

    @csrf_protected # Verify this is not CSRF, or fail
    def POST(self):
        auth_form = get_form()
        if not auth_form.validates():
            flash('error', 'form validation failed')
            return render.form(get_form())

        is_ipv4 = web.net.validipaddr(auth_form['ipaddr'].value)
        is_ipv6 = web.net.validip6addr(auth_form['ipaddr'].value)
        if is_ipv4 == False and is_ipv6 == False:
            flash('error', '%s is not a valid ipv4/6 address' % auth_form['ipaddr'].value)
            return render.form(get_form())

        if session.already_authorized:
            flash('error', '%s is already authorized' % auth_form['ipaddr'].value)
            return render.form(get_form())
        
        if session.auth_ip_count <= MAX_AUTH_IP_COUNT - 1 or session.user['privilege'] == 1:
            web.debug('Authorising ipaddr=%s' % auth_form['ipaddr'].value)
            web.header('Content-Type', 'text/html')
            if is_ipv4: result = run_ipt_cmd(auth_form['ipaddr'].value, 'I')
            if is_ipv6: result = run_ipt6_cmd(auth_form['ipaddr'].value, 'I')       
            web.debug('iptables_update: %s' % [result])
            
            if result[0] == 0:
                db_result = db.insert('ipaddrs',
                                      user_id=session.user['ID'],
                                      ipaddr=auth_form['ipaddr'].value)
                web.debug('db.insert: %s' % db_result)
                session.auth_ip_count += 1
                flash('success', 'succesfully authorized %s' % auth_form['ipaddr'].value)
                if is_redirected():
                    web.debug('is_redirected()=%s' % is_redirected()) 
                    return render.redirect(get_redirect_page())
                else:
                    return render.form(get_form())
            
            else:
                flash('error', 'error authorizing %s' % auth_form['ipaddr'].value)
                return render.form(get_form())

        else:
            flash('error', 'exceeded %s maximim authorized IPs' % MAX_AUTH_IP_COUNT)                          
            return render.form(get_form())


class Delete:
    
    def GET(self):
        try:
            if session.user:
                frm = get_form(name='delete')
                if not frm.inputs:flash('success', """all IP addresses de-authorized, please <a href="/add">authorize</a> one""")
                return render.form(frm)
            else:
                raise web.seeother('/login')                

        except Exception as e:
            web.debug(traceback.print_exc())
            raise web.seeother('/login')

    @csrf_protected # Verify this is not CSRF, or fail
    def POST(self):
        auth_form = get_form()
        if not auth_form.validates():
            flash('error', 'form validation failed')
            return render.form(get_form(name='delete'))

        is_ipv4 = web.net.validipaddr(auth_form['ipaddr'].value)
        is_ipv6 = web.net.validip6addr(auth_form['ipaddr'].value)
        if is_ipv4 == False and is_ipv6 == False:
            flash('error', '%s is not a valid ipv4/6 address' % auth_form['ipaddr'].value)
            return render.form(get_form(name='delete'))
        
        web.debug('De-authorising ipaddr=%s' % auth_form['ipaddr'].value)
        web.header('Content-Type', 'text/html')
        db_result = db.delete('ipaddrs', where="user_id=%s AND ipaddr='%s'" % (session.user['ID'],
                                                                               auth_form['ipaddr'].value))
        web.debug('db.delete: %s' % db_result)
        if db_result == 0: db_result = 1
        for i in range(0, db_result):
            if is_ipv4: result = run_ipt_cmd(auth_form['ipaddr'].value, 'D')
            if is_ipv6: result = run_ipt6_cmd(auth_form['ipaddr'].value, 'D') 
            web.debug('iptables_update: %s' % [result])
        session.auth_ip_count -= 1
        flash('success', '%s de-authorized' % auth_form['ipaddr'].value)
        return render.form(get_form(name='delete'))

class DDNSIndex:

    ddns_add_form = web.form.Form(web.form.Textbox('domain', web.form.notnull))
    def GET(self):
        try:
            if 'user' in session:
                domains = db.query('SELECT * FROM DDNS WHERE user_id=$user_id',
                       vars={'user_id': session.user['ID']})
                return render.ddns(domains, DDNSIndex.ddns_add_form())
            else:
                web.seeother('/login')
        except Exception as e:
            flash('error', 'Please update the database schema. See README for details.')
            web.debug(traceback.print_exc())
            raise web.seeother('/')

class DDNSAdd:
    
    @csrf_protected # Verify this is not CSRF, or fail
    def POST(self):
        form = DDNSIndex.ddns_add_form()
        if not form.validates():
            flash('error', 'form validation failed')
            raise web.seeother('/ddns')
        
        web.debug('Adding domain=%s' % form['domain'].value)
        web.header('Content-Type', 'text/html')
        db_result = db.insert('DDNS',
                                  user_id=session.user['ID'],
                                  domain=form['domain'].value)
        web.debug('db.insert: %s' % db_result)
        flash('success', 'succesfully added %s' % form['domain'].value)
        return web.seeother('/ddns')
 
class DDNSDelete:

    @csrf_protected # Verify this is not CSRF, or fail
    def POST(self):
        form = DDNSIndex.ddns_add_form()

        if not form.validates():
            flash('error', 'form validation failed')
            raise web.seeother('/ddns')

        web.debug('Removing domain=%s' % form['domain'].value)
        web.header('Content-Type', 'text/html')
        db_result = db.delete('DDNS', where="user_id=%s AND domain='%s'" % (session.user['ID'],
                                                                               form['domain'].value))
        web.debug('db.delete: %s' % db_result)
        flash('success', '%s removed' % form['domain'].value)
        return web.seeother('/ddns')        

# Adds a wsgi callable for uwsgi
application = app.wsgifunc()
if __name__ == "__main__":
    app.run()
