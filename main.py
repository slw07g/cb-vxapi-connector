import hashlib
import json
import logging
import os
import threading
import time
import traceback

from celery import group
from tasks import analyze_binary
from cbint.analysis import AnalysisResult
import cbint.globals
import xmlrpc.server
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from cbint.binary_database import BinaryDetonationResult
from cbint.detonation import BinaryDetonation
from peewee import fn

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


MAX_SCANS = 4
MAX_SCANS_PER_MINUTE = 20
MAX_SCANS_PER_HOUR = 200
SCAN_NUM = 0
 
# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

class VxAPIObject(BinaryDetonation):
    def __init__(self, name ):
        try:
            super().__init__(name)
        except:
          print(traceback.format_exc())
          raise Exception
        

    def queue_binaries(self):
        global SCAN_NUM
        global MAX_SCANS_PER_HOUR
        global MAX_SCANS_PER_MINUTE

        try:
            scan_group = list()
            logger.debug('queuing binaries!')
            for i in range(MAX_SCANS):
                binary = next(self.binaries_to_scan())
                md5 = binary[2]                
                scan_group.append(analyze_binary.s(md5))
                logger.debug('Queued md5: {0}'.format(md5))
                SCAN_NUM += 1
                if not SCAN_NUM % MAX_SCANS_PER_MINUTE:
                    if not SCAN_NUM % MAX_SCANS_PER_HOUR:
                        logger.debug('VxAPI Quota Throttling... pausing for 1 hour')
                        time.sleep(3600)
                        SCAN_NUM = 0
                    else:
                        logger.debug('VxAPI Quota Throttling...pausing for 60 seconds')
                        time.sleep(60)
                        
            job = group(scan_group)

            result = job.apply_async()
            while not result.ready():
                time.sleep(.1)

            if result.successful():
                for analysis_result in result.get():
                    if analysis_result:
                        if analysis_result.last_error_msg:
                            self.report_failure_detonation(analysis_result)
                            logger.debug('Last Error Message: {0}'.format(analysis_result.last_error_msg))
                        elif analysis_result.binary_not_available:
                            self.report_binary_unavailable(analysis_result)
                        else:
                            self.report_successful_detonation(analysis_result)
            else:
                logger.error(result.traceback())
        except:
            logger.error(traceback.format_exc())
            time.sleep(5)
	
    def start(self):
        logger.debug("Starting thread...")
        self.worker_thread = threading.Thread(target=self.run)
        self.worker_thread.start()
        logger.debug("Thread started!")

    def run(self):
        while (True):
            self.queue_binaries()

    def stop(self):
        self.worker_thread.join()
        self.close() #close db


def main():
    vxapi_object = VxAPIObject("vxapiconnector")

    vxapi_object.set_feed_info(name='HybridAnalysis', summary="VxAPI harnesses the power of Payload Security's Falcon Sandbox which uses behavioral and static analysis techniques to detect threats.",                                                                                                                          
                                              tech_data="A VxAPI private API key is required to use this feed. There are no requirements to share any data with Carbon Black to use this feed. However, binaries may be shared with vxapi.",
                                              provider_url="https://www.hybrid-analysis.com/",
                                              icon_path='vxapi-logo.png', display_name="HybridAnalysisVxAPI")
    vxapi_object.start()
    
    #rpc interface to the rpcinterface in cbrprcinterface.py
    server = SimpleXMLRPCServer(('0.0.0.0', 9005),
                            requestHandler=RequestHandler)
    server.register_introspection_functions()
    server.register_instance(vxapi_object)

    try:
            # Run the server's main loop
        server.serve_forever()
    except BaseException as bae:
        logger.debug("VxAPI error {}".format(str(e)))
    finally:
        vxapi_object.stop()


if __name__ == '__main__':
    main()
