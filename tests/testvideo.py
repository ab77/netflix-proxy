#!/usr/bin/env python

"""
Version : 1.0

Automatically play back Netflix titles.

Uses Selenium Python bindings for WebDriver.

Requires [ChromeDriver](https://sites.google.com/a/chromium.org/chromedriver/)

Author: Anton Belodedenko (anton@belodedenko.me)
Date: 04/2015
"""

import os, sys, time, argparse, logging, traceback, inspect
from StringIO import StringIO
from uuid import uuid1
from functools import wraps
from pprint import pprint

from settings import (DEFAULT_PROXY,                      
                      DEFAULT_HOST,
                      DEFAULT_PLAYBACK,
                      DEFAULT_TIMEOUT,
                      DEFAULT_TRIES,
                      DEFAULT_DELAY,
                      DEFAULT_BACKOFF,
                      DEFAULT_TITLEID)

CWD = os.path.dirname(os.path.realpath(__file__))

log = logging.getLogger(__name__)        
log.setLevel(logging.DEBUG)
stdout = logging.StreamHandler(sys.stdout)
stdout.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
log.addHandler(stdout)

try:
    from selenium import webdriver
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException

except ImportError:
    log.error('Python module "selenium" not found, please run "pip install selenium".')
    exit(1)
        

def args():
    parser = argparse.ArgumentParser()
    sp = parser.add_subparsers()    
    html5 = sp.add_parser('netflix')
    html5.add_argument('provider', action='store_const', const='netflix', help=argparse.SUPPRESS)
    html5.add_argument('--email', type=str, required=True, help='Netflix username')
    html5.add_argument('--password', type=str, required=True, help='Netflix password')
    html5.add_argument('--seconds', type=int, default=DEFAULT_PLAYBACK, help='playback time per title in seconds (default: %i)' % DEFAULT_PLAYBACK)
    html5.add_argument('--titleid', type=int, default=DEFAULT_TITLEID, help=' (default: %i)' % DEFAULT_TITLEID)
    args = parser.parse_args()
    log.info(args)
    return args


def retry(ExceptionToCheck, tries=DEFAULT_TRIES, delay=DEFAULT_DELAY, backoff=DEFAULT_BACKOFF, logger=log, cdata='method=%s()' % inspect.stack()[0][3]):
    """Retry calling the decorated function using an exponential backoff.

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
    """
    def deco_retry(f):

        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 0:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck, e:
                    msg = "%s, retrying in %d seconds (mtries=%d): %s" % (repr(e), mdelay, mtries, str(cdata))
                    if logger:
                        logger.warning(msg)
                    else:
                         sys.stderr.write('WARNING: %s\n' % msg)
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)

        return f_retry  # true decorator

    return deco_retry


class BaseVideoPlaybackTestClass():

    proxy = DEFAULT_PROXY


class VideoPlaybackTestClassNetflix(BaseVideoPlaybackTestClass):    

    host = DEFAULT_HOST
    playback_secs = DEFAULT_PLAYBACK
    timeout = DEFAULT_TIMEOUT
    title_id = DEFAULT_TITLEID


    def __init__(self):
        self.driver = self.buildDriver()


    def buildDriver(self):
        options = webdriver.ChromeOptions()
        args = ['--user-data-dir=%s/ChromeProfile' % CWD,
                '--disable-session-crashed-bubble',                
                '--disable-save-password-bubble',
                '--disable-permissions-bubbles',
                '--bwsi',
                '--disable-extensions',
                '--no-sandbox']

        if self.proxy:
            options.add_argument('--proxy-server=%s' % self.proxy)        

        options.add_experimental_option('excludeSwitches', ['disable-component-update',
                                                            'ignore-certificate-errors'])
        for arg in args:
            options.add_argument(arg)

        chromedriver = '%s/chromedriver' % CWD
        return webdriver.Chrome(chromedriver, chrome_options=options)


    @retry(Exception)
    def waitForHomePage(self):
        self.driver.get('https://%s/' % self.host)
        assert 'Netflix' in self.driver.title
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForHomePage'))
        return self.driver.current_url


    @retry(Exception)
    def waitForSignOutPage(self):
        self.driver.get('https://%s/SignOut' % self.host)
        assert 'Netflix' in self.driver.title        
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSignOutPage'))
        return self.driver.current_url


    @retry(Exception)
    def waitForSignInPage(self):
        self.driver.get('https://%s/Login' % self.host)
        assert 'Netflix' in self.driver.title
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSignInPage'))
        return self.driver.current_url


    @retry(Exception)
    def waitForPlayer(self, title_id):
        url = 'https://%s/watch/%s' % (self.host, title_id)
        self.driver.get(url)
        assert 'Netflix' in self.driver.title
        assert url in self.driver.current_url
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForPlayer'))
        return self.driver.current_url

 
    @retry(Exception)
    def waitForSignInEmailElementByName(self):
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSignInEmailElement'))
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.NAME, 'email'))
        )

  
    @retry(Exception)
    def waitForSignInPasswordElementByName(self):
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSignInPasswordElement'))
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.NAME, 'password'))
        )
   

    @retry(Exception)
    def waitForSignInFormButtonElementByXPath(self):
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSignInFormButtonElement'))
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.XPATH, "//button[@type='submit']"))
        )


    @retry(Exception)
    def waitForPlayerControlsByClassName(self):
        self.driver.save_screenshot('%s.png' % 'waitForPlayerControls')
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.CLASS_NAME, 'player-controls-wrapper'))
        )    


    @retry(Exception)
    def waitForSliderByClassName(self):
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSlider'))
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.CLASS_NAME, 'player-slider'))
        )


    def enablePlayerDiagnostics(self):
        actions = ActionChains(self.driver)
        actions.key_down(Keys.CONTROL).key_down(Keys.ALT).key_down(Keys.SHIFT).send_keys('d').perform()


    def enablePlayerControls(self):
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.END).perform()


    @retry(Exception)
    def getPlayerDiagInfo(self):
        js = """return document.evaluate('//*[@id="netflix-player"]/div[1]/div/div[2]/textarea', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue.value;"""
        return self.driver.execute_script(js)


    def dumpPlayerDiagInfoDict(self,):
        s = StringIO(self.getPlayerDiagInfo())
        d = dict()
        for line in s:
            if not line == '\n':
                kvlst = line.strip().split(': ')
                val = ''
                try:
                    val = kvlst[1].strip()
                except:
                    pass
                d[kvlst[0].strip()] = val

        return d


    def VideoPlaybackTest(self):        
        log.info('self.waitForSignOutPage()=%s' % self.waitForSignOutPage())
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSignOutPage'))
        
        log.info('self.waitForHomePage()=%s' % self.waitForHomePage())
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForHomePage'))
        
        log.info('self.waitForSignInPage()=%s' % self.waitForSignInPage())
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSignInPage'))
        
        self.waitForSignInEmailElementByName().clear()
        self.waitForSignInEmailElementByName().send_keys(self.email)
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSignInEmailElement'))
        
        self.waitForSignInPasswordElementByName().clear()
        self.waitForSignInPasswordElementByName().send_keys(self.password)
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSignInPasswordElement'))
 
        self.waitForSignInFormButtonElementByXPath().click()
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSignInFormButtonElement'))

        log.info('self.waitForPlayer()=%s' % self.waitForPlayer(self.title_id))
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForPlayer'))

        self.waitForPlayerControlsByClassName()
        self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForPlayerControls'))

        self.enablePlayerDiagnostics()

        for i in xrange(1, self.playback_secs):
            self.enablePlayerControls()
            log.info('time=%s' % (self.waitForSliderByClassName().text))
            self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'waitForSlider'))

            diags = self.dumpPlayerDiagInfoDict()
            log.info('diags=%s' % diags)
            assert 'Playing' in diags['Rendering state']
            if i % 5 == 0:
                self.driver.save_screenshot('%s/artifacts/%s.png' % (CWD, 'VideoPlaybackTest', str(i)))
            time.sleep(1)

        return True


if __name__ == '__main__':
    arg = args()    
    if arg.provider in ['netflix']:
        nflx = VideoPlaybackTestClassNetflix()
        nflx.email = arg.email
        nflx.password = arg.password    
        nflx.playback_secs = arg.seconds
        nflx.title_id = str(arg.titleid)
        try:
            nflx.VideoPlaybackTest()
            
        except Exception as e:
            log.error(traceback.print_exc())
            exit(1)
            
        finally:
            nflx.driver.close()
