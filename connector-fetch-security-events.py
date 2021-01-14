from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, convert_datetime_to_unix_time

import concurrent.futures
import datetime
import dateparser
import json
import math
import requests


CONNECTOR_NAME = "fetch-security-events"
PRODUCT = "Logz.io"
VENDOR = "Logz.io"
BASE_URL = "https://api.logz.io/"
TRIGGERED_RULES_API_SUFFIX = "v2/security/rules/events/search"
SORTING_FIELD_INDEX = 0
SORTING_DESCENDING_INDEX = 1
SEVERITIES = {'INFO': -1, 'LOW': 40, 'MEDIUM': 60, 'HIGH': 80, 'SEVERE': 100} # maps logzio severity values to siemplify severities
DEFAULT_PAGE_SIZE = 25
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 1000


@output_handler
def main():
    alerts = []  # The main output of each connector run
    siemplify = SiemplifyConnectorExecution()  # Siemplify main SDK wrapper
    siemplify.script_name = CONNECTOR_NAME

    logzio_api_token = siemplify.extract_connector_param("logzio_token", is_mandatory=True)
    if logzio_api_token == "":
        siemplify.LOGGER.error("Error occurred: no Logzio API token! Exiting.")
        raise ValueError
    logzio_region = siemplify.extract_connector_param("logzio_region", is_mandatory=False, default_value="")
    
    events_response = execute_logzio_api(siemplify, logzio_api_token, logzio_region)
    if events_response is not None:
        alerts = create_alerts_array(siemplify, events_response, logzio_api_token, logzio_region)

    siemplify.LOGGER.info("Total {} alerts will be returned to Siemplify".format(len(alerts)))
    siemplify.return_package(alerts)
    
    
def create_request_body_obj(siemplify, page_number=1):
    """ Creates request to send to Logz.io API """
    request_body = {}
    from_date, to_date = get_dates(siemplify)
    search_term = siemplify.extract_connector_param("search_term", is_mandatory=False)
    severities = siemplify.extract_connector_param("severities", is_mandatory=False)
    sort = siemplify.extract_connector_param("sort", is_mandatory=False)
    page_size = siemplify.extract_connector_param("page_size", is_mandatory=False, default_value=DEFAULT_PAGE_SIZE, input_type=int)
    if page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE:
        siemplify.LOGGER.warn("Invalid page size. Should be betwwen {} and {}. Reverting to default page size: {}".format(MIN_PAGE_SIZE, MAX_PAGE_SIZE, DEFAULT_PAGE_SIZE))
        page_size = DEFAULT_PAGE_SIZE
    request_body["filter"] = {}
    request_body["filter"]["timeRange"] = dict(fromDate=from_date, toDate=to_date)
    if search_term != None:
        request_body["filter"]["searchTerm"] = search_term
    if severities != None:
        request_body["filter"]["severities"] = [s.strip() for s in severities.split(",")]
    if sort != None:
        request_body["sort"] = get_sort_array(sort)
    request_body["pagination"] = dict(pageNumber=page_number, pageSize=page_size)
    return request_body


def get_sort_array(sort_str):
    """ Creates the sort part of the request to Logz.io's API, from user input """
    sort_arr = []
    for sorting in sort_str.split(","):
        sort = sorting.strip().split(":")
        dict_obj = dict(field=sort[SORTING_FIELD_INDEX])
        if len(sort) == 2:
            dict_obj["descending"] = sort[SORTING_DESCENDING_INDEX]
        sort_arr.append(dict_obj)
    return sort_arr


def get_base_api_url(region):
    """ Returnes API url, in accordance to user's input """
    if region == "us" or region == "":
        return BASE_URL
    else:
        return BASE_URL.replace("api.", "api-{}.".format(region))


def fetch_security_events(api_token, req_body, region, siemplify):
    """
    Returnes security events from Logz.io.
    If error occured or no results found, returnes None
    """
    headers = {
        'Content-Type': 'application/json',
        'X-API-TOKEN': api_token
    }

    url = get_base_api_url(region) + TRIGGERED_RULES_API_SUFFIX
    siemplify.LOGGER.info("api url: {}".format(url))
    try:
        body = json.dumps(req_body)
        siemplify.LOGGER.info("Fetching security events from Logz.io")
        response = requests.post(url, headers=headers, data=body, timeout=5)
        siemplify.LOGGER.info("Status code from Logz.io: {}".format(response.status_code))
        if response.status_code == 200:
            events_response = json.loads(response.content)
            if events_response["total"] > 0:
                return events_response
            siemplify.LOGGER.warn("No resultes found to match your request")
            return None
        else:
            siemplify.LOGGER.error("API request returned {}".format(response.status_code))
    except Exception as e:
        siemplify.LOGGER.error("Error occurred while fetching security events from Logz.io:\n{}".format(e))
        return None
        

def create_event(siemplify, logzio_event):
    """
    Returns the digested data of a single Logz.io secutiry event
    """
    siemplify.LOGGER.info("Processing siemplify event for logzio security event: {}".format(logzio_event["alertEventId"]))
    event = {}
    try:
        event["StartTime"] =  logzio_event["alertWindowStartDate"]
        event["EndTime"] = logzio_event["alertWindowEndDate"]
        event["event_name"] = logzio_event["name"]
        event["device_product"] = PRODUCT # ie: "device_product" is the field name that describes the product the event originated from.
        event["alertEventId"] = logzio_event["alertEventId"]
        event["description"] = logzio_event["description"]
        event["alertSummary"] = logzio_event["alertSummary"]
        event["eventDate"] = logzio_event["eventDate"]
        event["severity"] = logzio_event["severity"]
        if "groupBy" in logzio_event:
            for k, v in logzio_event["groupBy"].items():
                event["groupBy.{}".format(k)] = v
        if "tags" in logzio_event:
            tags_counter = 0
            for tag in logzio_event["tags"]:
                event["tags.{}".format(tags_counter)] = tag
                tags_counter += 1
        event["hits"] = logzio_event["hits"]
    except Exception as e:
        siemplify.LOGGER.error("Error occurred while trying to process logzio event {}:{}\n Dropping event.".format(logzio_event["alertEventId"], e))
        return None
    return event
    
    
def create_alert(siemplify, event, logzio_event):
    """
    Returns an alert which is one event that contains one Logz.io secrutiry event
    """
    siemplify.LOGGER.info("Processing siempify alert for logzio security event: {}".format(logzio_event["alertId"]))
    alert_info = AlertInfo()
    
    try:
        alert_info.display_id = logzio_event["alertEventId"]
        alert_info.ticket_id = logzio_event["alertEventId"]
        alert_info.name = logzio_event["name"]
        alert_info.rule_generator = logzio_event["alertSummary"]
        alert_info.start_time = logzio_event["alertWindowStartDate"]
        alert_info.end_time = logzio_event["alertWindowEndDate"]
        alert_info.priority = SEVERITIES[logzio_event["severity"]]
        alert_info.device_vendor = VENDOR
        alert_info.device_product = PRODUCT
    except Exception as e:
        siemplify.LOGGER.error("Error occurred while trying to add event {} to alert: {}\n Dropping event.".format(logzio_event["alertEventId"], e))
        alert_info = None
    
    siemplify.LOGGER.info("Creating siempify alert for logzio security event: {}".format(logzio_event["alertId"]))
    try:
        if alert_info is not None and event is not None:
            alert_info.events.append(event)
        siemplify.LOGGER.info("Added Event {} to Alert {}".format(logzio_event["alertEventId"], logzio_event["alertId"]))
    except Exception as e:
        siemplify.LOGGER.error("Failed to process event {} for alert {}".format(logzio_event["alertEventId"], logzio_event["alertId"]))
        siemplify.LOGGER.exception(e)
        return None
    return alert_info
    

def create_alerts_array(siemplify, events_response, api_token, logzio_region):
    """
    Returns the alerts that will be injected to Siemplify.
    If a query has more results than the page size, the function will request all the relevant
    pages from Logz.io, and only then will create Siemplify events & alerts.
    """
    alerts = []
    collected_events = events_response["results"]
    num_collected_events = len(collected_events)
    total_results_available = int(events_response["total"])
    current_page = int(events_response["pagination"]["pageNumber"])
    num_pages = math.ceil(total_results_available/int(events_response["pagination"]["pageSize"]))
    siemplify.LOGGER.info("Request retrieved {} events from Logz.io".format(num_collected_events))
    siemplify.LOGGER.info("There are {} results in your Logz.io account that match your query".format(total_results_available))
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_pages) as executor:
        futures = []
        while num_pages > current_page:
            current_page += 1
            print("fetching page: {}".format(current_page))
            futures.append(executor.submit(execute_logzio_api, siemplify, api_token, logzio_region, current_page))
        for future in concurrent.futures.as_completed(futures):
            new_event = future.result()
            if new_event is not None:
                collected_events += new_event["results"]
                num_collected_events += len(new_event["results"])
                siemplify.LOGGER.info("Fetched {} events".format(len(new_event["results"])))
        
        if total_results_available != num_collected_events:
            siemplify.LOGGER.warn("Retrieved {} events out of {} available events. Only the retrieved events will be injected to Siemplify".format(num_collected_events, total_results_available))
    siemplify.LOGGER.info("Total collected: {}".format(len(collected_events)))
    
    latest_timestamp = siemplify.fetch_timestamp()
    for logzio_event in collected_events:
        event = create_event(siemplify, logzio_event)
        alert = create_alert(siemplify, event, logzio_event)
        if alert is not None:
            alerts.append(alert)
            siemplify.LOGGER.info("Added Alert {} to package results".format(logzio_event["alertId"]))
            current_end_time = int(logzio_event["eventDate"])
            if latest_timestamp < current_end_time:
                latest_timestamp = current_end_time
    
    save_latest_timestamp(siemplify, latest_timestamp)
    
    return alerts


def execute_logzio_api(siemplify, api_token, logzio_region, page_number=1):
    """ Sends request for security events to Logz.io and returnes the response, if applicable """
    try:
        siemplify.LOGGER.info("Fetching page number {}".format(page_number))
        new_request = create_request_body_obj(siemplify, page_number)
        new_events = fetch_security_events(api_token, new_request, logzio_region, siemplify)
        if new_events != None:
            return new_events
    except Exception as e:
        siemplify.LOGGER.error("Error occurred while fetching events from page {}: {}".format(page_number, e))
    return None
    

def get_dates(siemplify):
    """
    Returnes start time & end time for fetching security events from Logz.io.
    If it's the first run, the start time will be the start time the user inserted, otherwise
    it will be the latest saved timestamp with offset of +1 millisecond.
    The end date will always be now - 3 min.
    """
    start_time = siemplify.fetch_timestamp()
    siemplify.LOGGER.info("Fetched timestamp: {}".format(start_time))
    if start_time == 0:
        # first run
        siemplify.LOGGER.info("No saved latest timestamp. Using user's input.")
        start_time = siemplify.extract_connector_param("from_date", is_mandatory=True)
    else:
        milliseconds_delta = datetime.timedelta(milliseconds=100)
        start_time = (datetime.datetime.fromtimestamp(start_time) + milliseconds_delta).timestamp()
    end_time_delta = datetime.timedelta(minutes=3)
    now = datetime.datetime.now()
    end_time_datetime = now - end_time_delta
    end_time = end_time_datetime.timestamp()
    return str(start_time), str(end_time)
    

def save_latest_timestamp(siemplify, latest_timestamp_from_events):
    """
    Saves the latest timestamp.
    Latest timestamp will be the latest between the two: now - hour, or timestamp of latest event.
    """
    hour_ago_delta = datetime.timedelta(hours=1)
    hour_ago = (datetime.datetime.now() - hour_ago_delta).timestamp()
    latest = max(latest_timestamp_from_events, int(hour_ago))
    siemplify.LOGGER.info("Latest timestamp to save: {}".format(latest))
    siemplify.save_timestamp(new_timestamp=latest)
        
        
if __name__ == "__main__":
    main()
    