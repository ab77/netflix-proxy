#!/usr/bin/env python

'''
auth.py: basic web front-end to auth/de-auth ipaddrs using iptables.
author: anton@belodedenko.me
'''

import sys
from subprocess import Popen, PIPE

try:
    import web
    from web import form, net, ctx
except ImportError:
    sys.stderr.write('ERROR: Python module "web.py" not found, please run "pip install web.py".\n')
    sys.exit(1)

def get_public_ip():
    return web.ctx.get('HTTP_X_FORWARDED_FOR', web.ctx.get('ip', None))
        
def run_ipt_cmd(ipaddr, op):
    ipt_cmd = 'iptables -%s FRIENDS -s %s/32 -j ACCEPT -v && iptables-save > /etc/iptables/rules.v4 || iptables-save > /etc/iptables.rules && service docker restart && docker restart bind sniproxy' % (op, ipaddr)
    web.debug('DEBUG: ipaddr=%s, op=%s, ipt_cmd=%s' % (ipaddr, op, ipt_cmd))
    p = Popen(ipt_cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    output, err = p.communicate(b"input data that is passed to subprocess' stdin")
    rc = p.returncode
    return rc, err, output

urls = (
    '/auth', 'auth'
)
    
render = web.template.render('templates/')

authform = form.Form(
    form.Textbox('ipaddr', value=get_public_ip()),
    form.Checkbox('authorise', value='auth', checked=True),    
    validators = [web.form.Validator('invalid ipaddr',
                                     lambda i:net.validipaddr(i.ipaddr) == True)])

class auth:
    def GET(self):
        form = authform()
        return render.auth(form)

    def POST(self):
        form = authform()
        if not form.validates(): 
            return render.auth(form)
        else:
            if form['authorise'].checked:
                web.debug('Authorising ipaddr=%s' % form['ipaddr'].value)
                return run_ipt_cmd(form['ipaddr'].value, 'I')
            else:
                web.debug('De-authorising ipaddr=%s' % form['ipaddr'].value)
                return run_ipt_cmd(form['ipaddr'].value, 'D')

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
