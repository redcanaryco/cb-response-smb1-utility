#!/usr/bin/env python

import argparse
import Queue
import sys
import threading
from time import sleep

from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import Sensor
from cbapi.response.live_response_api import *
from cbapi.errors import *

# This is the key that we use to determine what the Automatic Update policy
# looks like on a given system. For reference, see the following article:
#
#   https://msdn.microsoft.com/en-us/library/dd939844(v=ws.10).aspx
# 
# Section "Registry keys for Automatic Update configuration options" contains
# the list of subkeys and possible values.
check_key = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1'


def log_err(msg):
    """Format msg as an ERROR and print to stderr.
    """
    msg = 'ERROR: {0}\n'.format(msg)
    sys.stderr.write(msg)


def log_info(msg):
    """Format msg as INFO and print to stdout.
    """
    msg = 'INFO: {0}\n'.format(msg)
    sys.stdout.write(msg)


def set_smb1_disabled(lr, sensor):
    try:
        lr.set_registry_value(check_key, 0) 
    except LiveResponseError, err:
        # We should not need to do this but the method to list registry keys
        # and values returns a server-side 500 error.
        if 'ERROR_FILE_NOT_FOUND' in str(err):
            lr.create_registry_key(check_key)
    finally:
        lr.set_registry_value(check_key, 0) 


def get_smb1_status(lr, sensor):
    try:
        sensor_name = sensor.computer_name.lower()
        
        resp = lr.get_registry_value(check_key)['value_data']
        if resp == 0:
            output = 'smb1_disabled'
        elif resp == 1:
            output = 'smb1_enabled_explicit'
    except LiveResponseError, err:
        if 'ERROR_FILE_NOT_FOUND' in str(err):
            output = 'smb1_enabled_default'
   
    return output


def process_sensor(cb, sensor, update=False, debug=False):
    """Do things specific to this sensor. For now:
        - Skip non-Windows endpoints
        - Output name of offline endpoints
        - Get SMB1 status of all that remain
    """
    sensor_name = sensor.computer_name.lower()

    if 'windows' in sensor.os_environment_display_string.lower():
        if 'online' not in sensor.status.lower():
            ret = '%s,%s' % (sensor_name, 'offline')
        else:
            try:
                if debug: log_info('{0} CBLR pending'.format(sensor_name))
                lr = cb.live_response.request_session(sensor.id)
                if debug: log_info('{0} CBLR established (id:{1})'.format(sensor_name, str(lr.session_id)))
                smb1_status = get_smb1_status(lr, sensor)

                # If we're asked to update, only update if the key exists and
                # AU is disabled. If the key does not exist, we'll assume it's
                # because the system isn't domain joined or otherwise not
                # subject to policy, and we'll simply skip it and report
                # key_not_found.
                #
                # After updating, get the status again so that we're
                # accurately reporting the end state. 
                if update == True and 'smb1_enabled' in smb1_status:   
                    if debug: log_info('{0} CBLR updating AU config'.format(sensor_name))
                    set_smb1_disabled(lr, sensor)
                    smb1_status = get_smb1_status(lr, sensor)

                if debug: log_info('{0} CBLR closing (id:{1})'.format(sensor_name, str(lr.session_id)))
                lr.close()
            except TimeoutError:
                smb1_status = 'cblr_timeout'
            except Exception, err:
                log_err(err)
                smb1_status = 'error'
            
            ret = '%s,%s' % (sensor_name, smb1_status)
    
        sys.stdout.write(ret + '\n')

    return
        

def process_sensors(cb, query_base=None, update=False, max_threads=None,
                    debug=False):
    """Fetch all sensor objects associated with the cb server instance, and
    keep basic state as they are processed.
    """

    if query_base is not None:
        query_result = cb.select(Sensor).where(query_base)
    else:
        query_result = cb.select(Sensor)
    query_result_len = len(query_result)

    q = Queue()

    # unique_sensors exists because we sometimes see the same sensor ID
    # returned multiple times in the paginated query results for
    # cb.select(Sensor).  
    unique_sensors = set()

    for sensor in query_result:
        if sensor.id in unique_sensors:
            continue
        else:
            unique_sensors.add(sensor.id)
            q.put(sensor)

    threads = []
    while not q.empty():
        active_threads = threading.active_count()
        available_threads = max_threads - active_threads

        if available_threads > 0:
            for i in range(available_threads):
                sensor = q.get()
                t = threading.Thread(target=process_sensor, 
                                    args=(cb, sensor, update, debug))
                threads.append(t)
                t.start()

                if debug: log_info('Threads: {0}\tQ Size: {1}'.format(threading.active_count(), q.qsize()))

                if q.empty():
                    break
        else:
            if debug: log_info('No available threads. Waiting.')
            sleep(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=str, action="store",
                        help="The credentials.response profile to use.")
    parser.add_argument("--debug", action="store_true",
                        help="Write additional logging info to stdout.")
    parser.add_argument("--max-threads", type=int,  action="store",
                        default=5,
                        help="Maximum number of concurrent threads.")

    # Sensor query paramaters
    s = parser.add_mutually_exclusive_group(required=False)
    s.add_argument("--group-id", type=int,  action="store",
                        help="Target sensor group based on numeric ID.")
    s.add_argument("--hostname", type=str,  action="store",
                        help="Target sensor matching hostname.")
    s.add_argument("--ipaddr", type=str,  action="store",
                        help="Target sensor matching IP address (dotted quad).")

    # Options specific to this script
    parser.add_argument("--disable-smb1", action="store_true",
                        help="If SMB1 is enabled, disable it.")

    args = parser.parse_args()

    if args.profile:
        cb = CbEnterpriseResponseAPI(profile=args.profile)
    else:
        cb = CbEnterpriseResponseAPI()

    query_base = None
    if args.group_id:
        query_base = 'groupid:%s' % args.group_id
    elif args.hostname:
        query_base = 'hostname:%s' % args.hostname
    elif args.ipaddr:
        query_base = 'ipaddr:%s' % args.ipaddr

    process_sensors(cb, query_base=query_base, 
                    update=args.disable_smb1,
                    max_threads=args.max_threads,
                    debug=args.debug)
        

if __name__ == '__main__':

    sys.exit(main())
