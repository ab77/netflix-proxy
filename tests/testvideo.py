#!/usr/bin/env python

"""
Automatically play back Netflix titles.

Uses Selenium Python bindings for WebDriver.

Requires [ChromeDriver](https://sites.google.com/a/chromium.org/chromedriver/)

Author: Anton Belodedenko (anton@belodedenko.me)
Date: 04/2015
"""

from __future__ import division
import os, sys, time, argparse, logging, traceback, inspect
from StringIO import StringIO
from uuid import uuid1
from functools import wraps
from pprint import pprint

from settings import (VERSION,
                      DEFAULT_PROXY,                      
                      DEFAULT_NFLX_HOST,
                      DEFAULT_HULU_HOST,
                      DEFAULT_PLAYBACK,
                      DEFAULT_TIMEOUT,
                      DEFAULT_TRIES,
                      DEFAULT_DELAY,
                      DEFAULT_BACKOFF,
                      DEFAULT_NFLX_TITLEID,
                      DEFAULT_HULU_TITLEID)

CWD = os.path.dirname(os.path.realpath(__file__))
ARTIFACTS_DIR = '%s/artifacts' % CWD

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
    sp = parser.add_subparsers(help='version %s' % VERSION)
    netflix = sp.add_parser('netflix')
    netflix.add_argument('provider', action='store_const', const='netflix', help=argparse.SUPPRESS)
    netflix.add_argument('--email', type=str, required=True, help='Netflix username')
    netflix.add_argument('--password', type=str, required=True, help='Netflix password')
    netflix.add_argument('--seconds', type=int, default=DEFAULT_PLAYBACK, help='playback time per title in seconds (default: %i)' % DEFAULT_PLAYBACK)
    netflix.add_argument('--titleid', type=int, default=DEFAULT_NFLX_TITLEID, help='Netflix title_id to play (default: %i)' % DEFAULT_NFLX_TITLEID)
    netflix.add_argument('--tries', type=int, default=DEFAULT_TRIES, help='Playback restart attempts (default: %i)' % DEFAULT_TRIES)    
    hulu = sp.add_parser('hulu')
    hulu.add_argument('provider', action='store_const', const='hulu', help=argparse.SUPPRESS)
    hulu.add_argument('--email', type=str, required=True, help='Hulu username')
    hulu.add_argument('--password', type=str, required=True, help='Hulu password')
    hulu.add_argument('--seconds', type=int, default=DEFAULT_PLAYBACK, help='playback time per title in seconds (default: %i)' % DEFAULT_PLAYBACK)
    hulu.add_argument('--titleid', type=int, default=DEFAULT_HULU_TITLEID, help='Hulu title_id to play (default: %i)' % DEFAULT_HULU_TITLEID)
    hulu.add_argument('--tries', type=int, default=DEFAULT_TRIES, help='Playback restart attempts (default: %i)' % DEFAULT_TRIES)    
    args = parser.parse_args()
    return args


def retry(ExceptionToCheck, tries=DEFAULT_TRIES, delay=DEFAULT_DELAY, backoff=DEFAULT_BACKOFF, logger=log, cdata=inspect.stack()[0][3]):
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
                    args[0].driver.save_screenshot('%s/%s.png' % (ARTIFACTS_DIR, cdata))
                    if logger:
                        logger.warning(msg)
                        logging.exception("Exception")
                    else:
                         sys.stderr.write('%s\n' % msg)
                         sys.stderr.write(traceback.print_exc())
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)

        return f_retry  # true decorator

    return deco_retry


class BaseVideoPlaybackTestClass():

    proxy = DEFAULT_PROXY
    playback_secs = DEFAULT_PLAYBACK
    timeout = DEFAULT_TIMEOUT

    @retry(Exception, cdata='buildDriver')
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

    
    def __init__(self):
        self.driver = self.buildDriver()

        
class VideoPlaybackTestClassNetflix(BaseVideoPlaybackTestClass):    

    host = DEFAULT_NFLX_HOST
    title_id = DEFAULT_NFLX_TITLEID


    @retry(Exception, cdata='waitForHomePage')
    def waitForHomePage(self):
        url = 'https://%s/' % self.host
        self.driver.get(url)
        log.debug('url=%s title=%s' % (self.driver.current_url, self.driver.title))
        assert url in self.driver.current_url
        return self.driver.current_url


    @retry(Exception, cdata='waitForSignOutPage')
    def waitForSignOutPage(self):
        self.driver.get('https://%s/SignOut' % self.host)
        log.debug('url=%s title=%s' % (self.driver.current_url, self.driver.title))
        assert 'Netflix' in self.driver.title        
        return self.driver.current_url


    @retry(Exception, cdata='waitForSignInPage')
    def waitForSignInPage(self):
        self.driver.get('https://%s/Login' % self.host)
        log.debug('url=%s title=%s' % (self.driver.current_url, self.driver.title))
        assert 'Netflix' in self.driver.title
        return self.driver.current_url


    @retry(Exception, cdata='waitForPlayer')
    def waitForPlayer(self, title_id):
        url = 'https://%s/watch/%s' % (self.host, title_id)
        self.driver.get(url)
        log.debug('url=%s title=%s' % (self.driver.current_url, self.driver.title))
        assert 'Netflix' in self.driver.title
        assert url in self.driver.current_url
        return self.driver.current_url

 
    @retry(Exception, cdata='waitForSignInEmailElementByName')
    def waitForSignInEmailElementByName(self):
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.NAME, 'email'))
        )

  
    @retry(Exception, cdata='waitForSignInPasswordElementByName')
    def waitForSignInPasswordElementByName(self):
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.NAME, 'password'))
        )
   

    @retry(Exception, cdata='waitForSignInFormButtonElementByXPath')
    def waitForSignInFormButtonElementByXPath(self):
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.XPATH, "//button[@type='submit']"))
        )


    @retry(Exception, cdata='waitForPlayerControlsByClassName')
    def waitForPlayerControlsByClassName(self):
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.CLASS_NAME, 'player-controls-wrapper'))
        )    


    @retry(Exception, cdata='waitForSliderByClassName')
    def waitForSliderByClassName(self):
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.CLASS_NAME, 'player-slider'))
        )


    def enablePlayerDiagnostics(self):
        actions = ActionChains(self.driver)
        actions.key_down(Keys.CONTROL).key_down(Keys.ALT).key_down(Keys.SHIFT).send_keys('d').perform()


    def enablePlayerControls(self):
        actions = ActionChains(self.driver)
        actions.send_keys(Keys.END).perform()


    @retry(Exception, cdata='getPlayerDiagInfo')
    def getPlayerDiagInfo(self):
        js = """return document.evaluate('//*[@id="netflix-player"]/div[1]/div/div[2]/textarea', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue.value;"""
        return self.driver.execute_script(js)


    @retry(Exception, cdata='dumpPlayerDiagInfoDict')
    def dumpPlayerDiagInfoDict(self,):
        s = StringIO(self.getPlayerDiagInfo())
        d = dict()
        for line in s:
            if not line == '\n':
                kvlst = line.strip().split(': ')
                val = ''
                try:
                    val = ': '.join(kvlst[1:]).strip()
                except:
                    pass
                d[kvlst[0].strip()] = val

        return d


    def VideoPlaybackTest(self):
        log.debug('self.waitForSignOutPage()=%s' % self.waitForSignOutPage())
        log.debug('self.waitForHomePage()=%s' % self.waitForHomePage())
        log.debug('self.waitForSignInPage()=%s' % self.waitForSignInPage())
        self.waitForSignInEmailElementByName().clear()
        self.waitForSignInEmailElementByName().send_keys(self.email)
        self.waitForSignInPasswordElementByName().clear()
        self.waitForSignInPasswordElementByName().send_keys(self.password)
        self.waitForSignInFormButtonElementByXPath().click()
        log.debug('self.waitForPlayer()=%s' % self.waitForPlayer(self.title_id))
        self.waitForPlayerControlsByClassName()
    
        self.enablePlayerDiagnostics()
        for i in xrange(1, self.playback_secs):
            self.enablePlayerControls()
            log.debug('time=%s' % (self.waitForSliderByClassName().text))
            diags = self.dumpPlayerDiagInfoDict()
            log.debug('diags=%s' % diags)
            assert 'Playing' in diags['Rendering state']
            time.sleep(1)

        self.driver.save_screenshot('%s/%s.png' % (ARTIFACTS_DIR, 'VideoPlaybackTestNflx'))
        
        return True
        

class VideoPlaybackTestClassHulu(BaseVideoPlaybackTestClass):    

    host = DEFAULT_HULU_HOST
    title_id = DEFAULT_HULU_TITLEID


    @retry(Exception, cdata='waitForHomePage')
    def waitForHomePage(self):
        self.driver.get('http://%s/' % self.host)
        log.debug('url=%s title=%s' % (self.driver.current_url, self.driver.title))
        assert 'Hulu' in self.driver.title        
        return self.driver.current_url


    @retry(Exception, cdata='waitForSignOutPage')
    def waitForSignOutPage(self):
        self.driver.get('http://%s/account/logout' % self.host)
        log.debug('url=%s title=%s' % (self.driver.current_url, self.driver.title))
        assert 'Hulu' in self.driver.title        
        return self.driver.current_url


    @retry(Exception, cdata='waitForSignInPopUpByXPath')
    def waitForSignInPopUpByXPath(self):
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.XPATH, '//*[@id="user-menu"]/li[2]/a'))
        )


    @retry(Exception, cdata='waitForSignInDummyEmailElementByXPath')
    def waitForSignInDummyEmailElementByXPath(self):
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.XPATH, '//*[@id="popup-body"]/div/div[3]/div[2]/input[3]'))
        )
    

    @retry(Exception, cdata='waitForSignInEmailElementByXPath')
    def waitForSignInEmailElementByXPath(self):
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.XPATH, '//*[@id="login"]'))
        )

  
    @retry(Exception, cdata='waitForSignInPasswordElementByXPath')
    def waitForSignInPasswordElementByXPath(self):
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.XPATH, '//*[@id="password"]'))
        )
   

    @retry(Exception, cdata='waitForSignInFormButtonElementByXPath')
    def waitForSignInFormButtonElementByXPath(self):
        return WebDriverWait(self.driver, self.timeout).until(
            EC.presence_of_element_located((By.XPATH, '//*[@id="popup-body"]/div/div[3]/div[5]/a'))
        )
    

    @retry(Exception, cdata='waitForPlayerUrl')
    def waitForPlayerUrl(self, title_id):
        url = 'http://%s/watch/%s' % (self.host, title_id)
        self.driver.get(url)
        log.debug('url=%s title=%s' % (self.driver.current_url, self.driver.title))
        assert 'Watch South Park Online - Cartman Gets an Anal Probe' in self.driver.title
        assert url in self.driver.current_url
        return self.driver.current_url


    @retry(Exception, cdata='getPlayerCurrentTime')
    def getPlayerCurrentTime(self):
        js = "return window.Hulu.videoPlayerApp._dashPlayer.getCurrentTime()"
        return self.driver.execute_script(js)


    @retry(Exception, cdata='getPlayerCurrentVideoId')
    def getPlayerCurrentVideoId(self):
        js = "return window.Hulu.videoPlayerApp._dashPlayer.getCurrentVideoId()"
        return self.driver.execute_script(js)


    @retry(Exception, cdata='waitForPlayer')
    def waitForPlayer(self):
        assert self.getPlayerCurrentVideoId() == int(self.title_id)
        

    @retry(Exception, cdata='waitForAdsToFinish')
    def waitForAdsToFinish(self):
        assert self.getPlayerCurrentTime() > 0
    

    def VideoPlaybackTest(self):
        self.driver.set_window_size(1280, 1024)
        log.debug('self.waitForSignOutPage()=%s' % self.waitForSignOutPage())
        log.debug('self.waitForHomePage()=%s' % self.waitForHomePage())
        log.debug('window_size=%s' % self.driver.get_window_size())
        log.debug('self.waitForPlayerUrl()=%s' % self.waitForPlayerUrl(self.title_id))
        self.waitForSignInPopUpByXPath().click()
        self.waitForSignInDummyEmailElementByXPath().click()        
        self.waitForSignInEmailElementByXPath().clear()
        self.waitForSignInEmailElementByXPath().send_keys(self.email)
        self.waitForSignInPasswordElementByXPath().clear()
        self.waitForSignInPasswordElementByXPath().send_keys(self.password)
        self.waitForSignInFormButtonElementByXPath().click()
        self.waitForPlayer()
        self.waitForAdsToFinish()
        
        for i in xrange(1, self.playback_secs):
            progress = round(i / self.playback_secs * 100, 0)
            log.debug('progress=%s%% current_time=%s video_id=%s' % (str(progress),
                                                                     self.getPlayerCurrentTime(),
                                                                     self.getPlayerCurrentVideoId()))
            time.sleep(1)

        self.driver.save_screenshot('%s/%s.png' % (ARTIFACTS_DIR, 'VideoPlaybackTestHulu'))
        
        return True


if __name__ == '__main__':
    arg = args()
    rc = arg.tries
    result = False
    for i in xrange(0, arg.tries):
        log.debug('tries=%s/%s' % (str(i+1), arg.tries))
        if arg.provider in ['netflix']:            
            nflx = VideoPlaybackTestClassNetflix()
            nflx.email = arg.email
            nflx.password = arg.password    
            nflx.playback_secs = arg.seconds
            nflx.title_id = str(arg.titleid)
            try:
                result = nflx.VideoPlaybackTest()                
            except:
                logging.exception("Exception")
                pass

            finally:
                nflx.driver.close()
            
        elif arg.provider in ['hulu']:
            hulu = VideoPlaybackTestClassHulu()
            hulu.email = arg.email
            hulu.password = arg.password    
            hulu.playback_secs = arg.seconds
            hulu.title_id = str(arg.titleid)
            try:
                result = hulu.VideoPlaybackTest()
            except:
                logging.exception("Exception")
                pass

            finally:
                hulu.driver.close()

        if result:
            log.debug('result=%s' % str(i))
            rc = 0
            break
    
    exit(rc)
