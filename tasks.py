from celery import Celery,Task

app = Celery('vxapiconnector', backend='redis://localhost', broker='redis://localhost')
app.conf.task_serializer = "pickle"
app.conf.result_serializer = "pickle"
app.conf.accept_content = {"pickle"}

import cbapi
import datetime
import logging
import os
import requests
import time
import traceback
from cbint.analysis import AnalysisResult
from cbapi.response.models import Binary
from cbapi.response.rest_api import CbResponseAPI
import configparser
#TODO REMOVE USE OF GLOBALS TO SHARE INFO BETWEEN CONTEXTS


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

cfg_parser = configparser.ConfigParser()
try:
  cfg_parser.read("vxapiconnector.conf")
except:
  print(e)
  print(traceback.format_exc())
  
GlobalConfig = cfg_parser['general']


class CbAPITask(Task):
    _cb = None

    @property
    def cb(self):
        global GlobalConfig
        if self._cb is None:
            try:
                self._cb = CbResponseAPI(url=GlobalConfig.get("carbonblack_server_url"),
                           token=GlobalConfig.get("carbonblack_server_token"),
                           ssl_verify=GlobalConfig.getboolean("carbonblack_server_sslverify"))
            except Exception as e:
                self._cb = None
        return self._cb


@app.task(base=CbAPITask)
def analyze_binary(md5sum, cb_config=None):
    global GlobalConfig
    logger.debug("Analyzing md5: {0}".format(md5sum))

    try:
        analysis_result = AnalysisResult(md5sum)
        analysis_result.last_scan_date = datetime.datetime.now()


        binary_query = analyze_binary.cb.select(Binary).where("md5:{0}".format(md5sum))
        result = get_report(GlobalConfig.get('vxapi_token'), md5sum)
        if result and len(result) > 0:
            logger.debug(result)
            avdetect = int(result[0].get("av_detect"))
            threatscore = int(result[0].get("threat_score",0))
            malware_result = "Benign"
            summary = ""
            link = "https://www.hybrid-analysis.com/sample/" + result[0].get("sha256") + "?environmentId=" + str(result[0].get("environment_id"))
            score = 0
            if avdetect >= 25:
              summary = "High AV Score"
              score = avdetect
            if threatscore >= 60:
              summary = "High Threat Score"
              score = threatscore
            if avdetect >= 25 and threatscore >= 60:
              summary = "High AV Score & High Threat Score"
              score = 75
            if avdetect >= 25 or threatscore >= 60:
              malware_result = "[%d || %d] VxAPI report for %s\nLink: %s" % (avdetect , threatscore, md5sum, link)
        else:
            logger.debug('Empty result for {0}'.format(md5sum))
            malware_result = "No Result"
            summary = "N/A"
            score = 0
        analysis_result.score = score
        analysis_result.short_result = summary
        analysis_result.long_result = malware_result
        
        return analysis_result
    except:
        error = traceback.format_exc()
        analysis_result.last_error_msg = error
        return analysis_result


def get_report(api_token, resource_hash=None):

        class VXAPIQUOTAREACHED:
            pass
        data = {'hash': resource_hash}

        headers = {
            "User-Agent": "Falcon",
            'api-key': api_token,
        }
        resp = requests.sessions.Session().post('https://www.hybrid-analysis.com/api/v2/search/hash',
                                    headers=headers, data=data, verify=False)
        
        if resp.status_code == 429:
                logger.debug('VxAPI Quota Reached!!')
                logger.debug(resp.json())
                raise Exception()
        elif resp.status_code != 200:
            logger.debug(resp.json())
            raise Exception()

        logger.debug("VxAPI response = %s " % resp)
        logger.debug(resp.json())
        return resp.json()
