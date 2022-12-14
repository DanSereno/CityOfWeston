"""
SYNOPSIS

    pullLakeLevels.py <path to config> <path to log file folder>

DESCRIPTION

    Script to pull lake level data from VTScada REST endpoints.
    
REQUIREMENTS

    Python 3.5 or higher
    TODO - Enter all dependent libraries that do not come in the standard
           Python environment this script is expected to run in.  If a library
           must be installed, provide a brief indication of how it is to be 
           installed.  EX: (install via pip)  EX: (install via conda)  

AUTHOR

    Dan Sereno, AximGeoSpatial, 2022
    
UPDATES

    TODO - If this script was modified, indicate when it was modified, what
           modifications were performed, and by whom.
"""

import os, sys
import logging
from logging.handlers import RotatingFileHandler
import traceback
import configparser
import argparse
from typing import Dict
import base64
from arcgis.gis import GIS
import pandas as pd
import urllib
import json
from datetime import datetime
from datetime import date
import requests as req
from requests.auth import HTTPBasicAuth
from requests.compat import urljoin


# import arcpy
# below is code to try to catch arcpy import errors
try:
    import arcpy
    arcpy_imported = True
except:
    arcpy_imported = False
    exit_status = 1

def start_rotating_logging(log_path: str = None,
                           max_bytes: int = 100000,
                           backup_count: int = 2,
                           log_to_file: bool =True,
                           log_to_console: bool =True,
                           suppress_requests_messages: bool =True) -> logging.Logger:
    """
    This function starts logging with a rotating file handler.  If no log
    path is provided it will start logging in the same folder as the script,
    with the same name as the script.
    
    Parameters
    ----------
    log_path (str)
        The path to use in creating the log file
    max_bytes (int)
        The maximum number of bytes to use in each log file
    backup_count (int)
        The number of backup files to create
    log_to_file (bool)
        Log messages to log file (Default is True)
    log_to_console (bool)
        Log messages to the console/stdout (Default is True)
    suppress_requests_messages (bool)
        Suppress error messages/warnings from SSL
        and requests libraries (Default is True)
    
    Returns
    -------
    logging.logger: The logger object, ready to use
    """
    formatter = logging.Formatter(fmt="%(asctime)s - %(levelname)s - %(message)s",
                                  datefmt="%Y-%m-%d %H:%M:%S")
    
    # if no log path was provided, construct one
    script_path = sys.argv[0]
    script_folder = os.path.dirname(script_path)
    script_name = os.path.splitext(os.path.basename(script_path))[0]    
    if not log_path:
        log_path = os.path.join(script_folder, "{}.log".format(script_name))
        
    # start logging
    the_logger = logging.getLogger(script_name)
    the_logger.setLevel(logging.DEBUG)
    
    # if the logger doesn't have handlers, add them
    if not the_logger.handlers:
        if log_to_file:
            # add the rotating file handler
            log_handler = RotatingFileHandler(filename=log_path,
                                              maxBytes=max_bytes,
                                              backupCount=backup_count)
            log_handler.setLevel(logging.DEBUG)
            log_handler.setFormatter(formatter)
            the_logger.addHandler(log_handler)
        if log_to_console:
            # add the console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            console_handler.setFormatter(formatter)
            the_logger.addHandler(console_handler)
        
        # suppress SSL warnings in logs if instructed to
        if suppress_requests_messages:
            logging.getLogger("requests").setLevel(logging.WARNING)
            logging.getLogger("urllib3").setLevel(logging.WARNING)

    return the_logger

def is_valid_path(parser: str, path: str) -> str:
    """
    Check to see if a provided path is valid.  Works with argparse
    
    Parameters
    ----------
    parser (argparse.ArgumentParser)
        The argument parser object
    path (str)
        The path to evaluate whether it exists or not
        
    Returns
    ----------
    path (str)
        If the path exists, it is returned  if not, a 
        parser.error is raised.
    """      
    if not os.path.exists(path):
        parser.error("The path {0} does not exist!".format(path))
    else:
        return path
    
# Parse config file
def convert_AGOL_config(confFile: str) -> Dict:

	# Add the config file to a data frame
	df = pd.read_csv(confFile)

	# Create a dictionary from the config file (csv)
	convertedDict = df.to_dict()
	#print(convertedDict)

	return convertedDict

def getArcGISServerToken(url: str, userN: str, userPwd: str, logger: str = None) ->str:
    #logger.info("Getting token...")
    values = {'username': userN,
        'password': userPwd,
        'referer' : url,
        'f': 'json'}
    data =  urllib.parse.urlencode(values)
    data = data.encode('ascii')
    URL  = url + '/tokens/generateToken'
    req = urllib.request.Request(URL,data)
    with urllib.request.urlopen(req) as response:
        jres = json.load(response)

    return jres['token']    

# Create GIS object
def create_GIS(portal_url: str, user: str, password: str, logger: str) -> GIS:
    logger.info("Creating GIS...")
    try:
        gis = GIS(url=portal_url,
                    username=user,
                    password=password,
                    verify_cert=False)
    except Exception as e:
        logger.info("Creation of GIS failed!")
        logger.info(e.args)

    return gis

# Get lake level and pump station values
def get_values(user: str, pw: str, base: str) -> Dict:
    
    # Reporting location list
    locations = [
                    "'Pump Stations\BDD2\Level:value'",
                    "'Pump Stations\BDD1\Level:value'",
                    "'Pump Stations\ITDD1\Level:value'",
                    "'Pump Stations\ITDD2\Level:value'",
                    "'Pump Stations\ITDD3\Level:value'",
                    "'Lake Levels\BONBL\Level:Value'",
                    "'Lake Levels\HIBIS\Level:Value'",
                    "'Lake Levels\ISLWST\Level:Value'",
                    "'Lake Levels\MEAD\Level:Value'",
                    "'Lake Levels\PEACMN\Level:Value'",
                    "'Lake Levels\RACQCL\Level:Value'",
                    "'Lake Levels\SAVAN\Level:Value'",
                    "'Lake Levels\WHILLS\Level:Value'"
                ]

    # Define empty dictionaries to return level info
    levels_dict = {}
    
    # Get station and lake levels
    for location in locations:

        # Encode the location
        location_encoded = urllib.parse.quote(location)

        # Build query parameters
        path = r'?query=SELECT%20Timestamp,' + location_encoded + r'FROM%20History%20Order%20BY%20TIMESTAMP%20DESC%20LIMIT%201'

        # Build full URL
        full_url = urljoin(base, path)

        # Make the request
        r = req.get(full_url, auth = HTTPBasicAuth(user, pw))
        data = r.json()
        station = data['results']['fieldNames'][1].split('\\')[1]
        station_level = data['results']['values'][0][1]
        #print(fr"Station " + station + " level: " + str(station_level))

        # Get sample datetime
        sample_datetime = data['results']['values'][0][0]
        
        # Populate dictionary
        levels_dict[station] = [station_level, sample_datetime]
        
    return levels_dict

# Update the GIS related tables
def update_gis(data: Dict):
    arcpy.env.workspace = r"\\WGISAGS2\D$\GISInc_Working\LakeLevels\gisinc@WGISSQL1.sde"
    workspace = arcpy.env.workspace
    #print(fr"Data[1] - {data[1]}")

    # Update Lake Levels gauge table
    lake_level_table = 'LGIM_PROD.DBO.swLakeLevelGauge'
    lake_level_fields = ['NAME','LAKELEVEL','CONDITIONDATE']

    try:

        # Start edit session
        edit = arcpy.da.Editor(workspace)
        edit.startEditing(False, True)
        edit.startOperation()
        with arcpy.da.UpdateCursor(lake_level_table, lake_level_fields) as levelCursor:
            for level in levelCursor:

                # Iterate VTScada readings result dictionary
                for node, readings in data.items():

                     # Check PARENTID (level[0] from Weston's SDE table) against VTScada's dictionary
                    if level[0].lower() == node.lower():

                        # Set pool level from VTScada REST dictionary
                        pool_level = readings[0]

                        # Set Current_Pool attribute
                        level[1] = round(pool_level,2)

                        # Calculate percent full
                        #level[3] = round((pool_level / level[2]) * 100,2)

                        # Get sample date
                        level[2] = datetime.fromtimestamp(int(readings[1])).strftime('%m-%d-%Y %H:%M:%S')
                            
                        # Update Weston's SDE table
                        print(fr"Updating {level}...")
                        curReturn = levelCursor.updateRow(level)
                        print(fr"{curReturn}")
                        
        edit.stopOperation()
        edit.stopEditing(True)
    except arcpy.ExecuteError:
        arcpy.AddMessage(arcpy.GetMessages(2))

def main():
    """
    Main execution code
    """
    exit_status = 0
    
    # parse command line arguments - edit these descriptions and help
    #parser = argparse.ArgumentParser(description="TODO - Provide a brief description of what the script does")
    #parser.add_argument("configpath", help="The full path to the configuration file to use", 
                        #type=lambda x: is_valid_path(parser, x))
    #parser.add_argument("logfolder", help="The full path to the folder where logfiles will be stored",  
                        #type=lambda x: is_valid_path(parser, x))
    # example argument for optional flag
    #parser.add_argument("-p", "--publish", help="Publish data as hosted feature service", default=False, action="store_true")
    
    #args = parser.parse_args()
    config_path = r"D:\GISInc_Working\LakeLevels\config.ini" #args.configpath
    log_folder = r"D:\GISInc_Working\LakeLevels" #args.logfolder

    # make a few variables to use
    script_name_no_ext = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    script_folder = os.path.dirname(sys.argv[0])
    log_file = os.path.join(log_folder, "{}.log".format(script_name_no_ext))
    try:
        # get logging going
        logger = start_rotating_logging(log_path=log_file,
                                        max_bytes=100000,
                                        backup_count=2,
                                        log_to_console=True,
                                        log_to_file=True,
                                        suppress_requests_messages=True)       
        logger.info("")
        logger.info("--- Script Execution Started ---")
        logger.info("Running script using {}".format(sys.executable))
        
        # if arcpy did not import, log the message and quit
        if arcpy_imported == False:
            raise ValueError("Could not import arcpy.  Check licensing or the Python executable.")

        # read the config file
        the_config = configparser.ConfigParser()
        the_config.read(config_path)
        
        # # # # Put your code below here # # # # #
        # Get credentials
        user = the_config['REST']['user']
        pw = base64.b64decode(the_config['REST']['pw']).decode('utf-8')

        # Endpoint
        base = the_config['REST']['url']

        # Get the values
        values_dict = get_values(user,pw,base)

        # Update the GIS
        update_gis(values_dict)

        # # # # End your code above here # # # #
            
    except ValueError as e:
        exit_status = 1
        exc_traceback = sys.exc_info()[2]
        error_text = 'Line: {0} --- {1}'.format(exc_traceback.tb_lineno, e)
        try:
            logger.error(error_text)
        except NameError:
            print(error_text)       
    
    except Exception:
        exit_status = 1
        exc_traceback = sys.exc_info()[2]
        tbinfo = traceback.format_exc()
        error_text = 'Line: {0} --- {1}'.format(exc_traceback.tb_lineno, tbinfo)
        try:
            logger.error(error_text)
        except NameError:
            print(tbinfo)
    
    finally:
        # shut down logging
        try:
            logger.info("--- Script Execution Completed ---")
            logging.shutdown()
        except NameError:
            pass
        if exit_status == 0:
            sys.exit(0)
        else:
            print(str(exit_status))
            sys.exit(exit_status)
    
if __name__ == '__main__':
    main()
