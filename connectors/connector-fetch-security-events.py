from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, convert_datetime_to_unix_time

import concurrent.futures
import copy
import datetime
import dateparser
import distutils
import json
import math
import requests

CONNECTOR_NAME = "fetch-security-events"
PRODUCT = "Logz.io"
VENDOR = "Logz.io"
BASE_URL = "https://api.logz.io/"
TRIGGERED_RULES_API_SUFFIX = "v2/security/rules/events/search"
TRIGGERING_LOGS_API_SUFFIX = "v2/security/rules/events/logs/search"
SORTING_FIELD_INDEX = 0
SORTING_DESCENDING_INDEX = 1
SEVERITIES = {'INFO': -1, 'LOW': 40, 'MEDIUM': 60, 'HIGH': 80,
              'SEVERE': 100}  # maps logzio severity values to siemplify severities
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
    events_url = get_logzio_api_endpoint(siemplify, logzio_region, TRIGGERED_RULES_API_SUFFIX)
    events_response = get_logzio_events(siemplify, logzio_api_token, events_url)
    if events_response is not None and len(events_response) > 0:
        alerts = create_alerts_array(siemplify, events_response, logzio_api_token, events_url, logzio_region)

    siemplify.LOGGER.info("Total {} alerts will be returned to Siemplify".format(len(alerts)))
    siemplify.return_package(alerts)


def get_logzio_events(siemplify, api_token, url):
    payload = create_request_body_obj_events(siemplify)
    return do_pagination(siemplify, payload, url, api_token)


def create_request_body_obj_events(siemplify, page_number=1):
    """ Creates fetch events request to send to Logz.io API """
    request_body = {}
    from_date, to_date = get_dates(siemplify)
    search_term = siemplify.extract_connector_param("search_term", is_mandatory=False)
    severities = siemplify.extract_connector_param("severities", is_mandatory=False)
    page_size = siemplify.extract_connector_param("page_size", is_mandatory=False, default_value=DEFAULT_PAGE_SIZE,
                                                  input_type=int)
    enable_muted_events = bool(
        distutils.util.strtobool(siemplify.extract_connector_param("enable_muted_events", is_mandatory=False)))
    if enable_muted_events:
        siemplify.LOGGER.info("Muted events will be fetched, if exist")
    if page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE:
        siemplify.LOGGER.warn(
            "Invalid page size. Should be betwwen {} and {}. Reverting to default page size: {}".format(MIN_PAGE_SIZE,
                                                                                                        MAX_PAGE_SIZE,
                                                                                                        DEFAULT_PAGE_SIZE))
        page_size = DEFAULT_PAGE_SIZE
    request_body["filter"] = {}
    request_body["filter"]["timeRange"] = dict(fromDate=from_date, toDate=to_date)
    request_body["filter"]["includeMutedEvents"] = enable_muted_events
    if search_term != None:
        request_body["filter"]["searchTerm"] = search_term
    if severities != None:
        request_body["filter"]["severities"] = [s.strip() for s in severities.split(",")]
    request_body["sort"] = [{"field": "DATE", "descending": False}]
    request_body["pagination"] = dict(pageNumber=page_number, pageSize=page_size)
    siemplify.LOGGER.info("{}".format(request_body))
    return request_body


def get_base_api_url(region):
    """ Returnes API url, in accordance to user's input """
    if region == "us" or region == "":
        return BASE_URL
    else:
        return BASE_URL.replace("api.", "api-{}.".format(region))


def create_event(siemplify, logzio_event):
    """
    Returns the digested data of a single Logz.io secutiry event
    """
    siemplify.LOGGER.info(
        "Processing siemplify event for logzio security event: {}".format(logzio_event["alertEventId"]))
    event = {}
    try:
        event["StartTime"] = logzio_event["alertWindowStartDate"]
        event["EndTime"] = logzio_event["alertWindowEndDate"]
        event["event_name"] = logzio_event["name"]
        event[
            "device_product"] = PRODUCT  # ie: "device_product" is the field name that describes the product the event originated from.
        event["alertEventId"] = logzio_event["alertEventId"]
        event["description"] = logzio_event["description"]
        event["alertSummary"] = logzio_event["alertSummary"]
        event["eventDate"] = logzio_event["eventDate"]
        event["severity"] = logzio_event["severity"]
        if "groupBy" in logzio_event and logzio_event["groupBy"] is not None:
            for k, v in logzio_event["groupBy"].items():
                event["groupBy.{}".format(k)] = v
        if "tags" in logzio_event and logzio_event["tags"] is not None:
            tags_counter = 0
            for tag in logzio_event["tags"]:
                event["tags.{}".format(tags_counter)] = tag
                tags_counter += 1
        event["hits"] = logzio_event["hits"]
    except Exception as e:
        siemplify.LOGGER.error("Error occurred while trying to process logzio event {}:{}\n Dropping event.".format(
            logzio_event["alertEventId"], e))
        return None
    return event


def create_alert(siemplify, event, logs_events, logzio_event):
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
        siemplify.LOGGER.error("Error occurred while trying to add event {} to alert: {}\n Dropping event.".format(
            logzio_event["alertEventId"], e))
        alert_info = None

    siemplify.LOGGER.info("Creating siempify alert for logzio security event: {}".format(logzio_event["alertId"]))
    try:
        if alert_info is not None and event is not None:
            alert_info.events.append(event)
            siemplify.LOGGER.info(
                "Added Event {} to Alert {}".format(logzio_event["alertEventId"], logzio_event["alertId"]))
            if logs_events is not None and len(logs_events) > 0:
                alert_info.events += logs_events
                siemplify.LOGGER.info(f"Added {len(logs_events)} log events to Alert {logzio_event['alertId']}")
    except Exception as e:
        siemplify.LOGGER.error(
            "Failed to process event {} for alert {}".format(logzio_event["alertEventId"], logzio_event["alertId"]))
        siemplify.LOGGER.exception(e)
        return None
    return alert_info


def create_alerts_array(siemplify, collected_events, api_token, url, region):
    """
    Returns the alerts that will be injected to Siemplify.
    If a query has more results than the page size, the function will request all the relevant
    pages from Logz.io, and only then will create Siemplify events & alerts.
    """
    alerts = []
    latest_timestamp = siemplify.fetch_timestamp()
    add_raw_logs = bool(
        distutils.util.strtobool(siemplify.extract_connector_param("fetch_raw_logs", is_mandatory=False)))
    for logzio_event in collected_events:
        event = create_event(siemplify, logzio_event)
        log_events = []
        if add_raw_logs and event is not None:
            raw_logs = get_raw_logs(siemplify, logzio_event["alertEventId"], region, api_token)
            if raw_logs is not None and len(raw_logs) > 0:
                for log in raw_logs:
                    log_event = create_log_event(siemplify, log)
                    if log_event is not None:
                        log_events.append(log_event)
                siemplify.LOGGER.info(f"Collected {len(log_events)} raw logs for event {logzio_event['alertEventId']}")
        alert = create_alert(siemplify, event, log_events, logzio_event)

        if alert is not None:
            alerts.append(alert)
            siemplify.LOGGER.info("Added Alert {} to package results".format(logzio_event["alertId"]))
            current_end_time = int(logzio_event["eventDate"])
            if latest_timestamp < current_end_time:
                latest_timestamp = current_end_time

    save_latest_timestamp(siemplify, latest_timestamp)

    return alerts


def create_log_event(siemplify, log):
    """ Maps a Logz.io log to a Siemplify event """
    try:
        flattened = dict_to_flat(log)
        event = flattened
        event["StartTime"] = flattened["@timestamp"]
        event["EndTime"] = flattened["@timestamp"]
        event["event_name"] = flattened["type"]
        event["device_product"] = PRODUCT
        return event
    except Exception as e:
        siemplify.LOGGER.error(f"Error occurred while trying to create log event {log}:\n{e}")
        return None


def get_dates(siemplify):
    """
    Returns start time & end time for fetching security events from Logz.io.
    If it's the first run, the start time will be the start time the user inserted, otherwise
    it will be the latest saved timestamp with offset of +1 millisecond.
    The end date will always be now - 3 min.
    """
    start_time = siemplify.fetch_timestamp()
    siemplify.LOGGER.info("Fetched timestamp: {}".format(start_time))
    if start_time == 0:
        # first run
        siemplify.LOGGER.info("No saved latest timestamp. Using user's input.")
        start_time_str = siemplify.extract_connector_param("from_date", is_mandatory=True)
        if not start_time_str.isdigit():
            start_time = datetime.datetime.timestamp(
                dateparser.parse(start_time_str, date_formats=['%Y-%m-%dT%H:%M:%S.%f'], settings={'TIMEZONE': 'UTC'}))
        else:
            start_time = start_time_str
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


def get_logzio_api_endpoint(siemplify, region, suffix):
    """
    Returns the endpoint of Logz.io API.
    Prioritizing a custom endoint, if entered.
    If not, falling back to the regaular enspoints, based on the logzio_region (defaults to us).
    """
    custom_endpoint = siemplify.extract_connector_param("logzio_custom_endpoint", is_mandatory=False, default_value="")
    if custom_endpoint is not None and custom_endpoint != "":
        siemplify.LOGGER.info("Using custom endpoint: {}".format(custom_endpoint))
        return custom_endpoint + TRIGGERED_RULES_API_SUFFIX
    return get_base_api_url(region) + suffix


def get_raw_logs(siemplify, alertEventId, region, api_token):
    """ Retrieves all the logs that triggered the alert in Logz.io """
    logs = []
    siemplify.LOGGER.info(f"retrieving raw logs for event id: {alertEventId}")
    payload = {
        "filter": {
            "alertEventId": alertEventId
        },
        "pagination": {
            "pageNumber": 1,
            "pageSize": 100
        }
    }

    triggering_logs_url = get_logzio_api_endpoint(siemplify, region, TRIGGERING_LOGS_API_SUFFIX)
    logs = do_pagination(siemplify, payload, triggering_logs_url, api_token)
    return logs


def do_pagination(siemplify, payload, url, api_token):
    """ Returns array of the objects that need to be retrieved from logz.io (events/logs)"""
    max_allowed_errors_for_pagination = 5
    errors_on_pagination = 0
    results = []
    response = execute_logzio_api_call(siemplify, api_token, json.dumps(payload), url)
    if response is None:
        return None
    if response["results"] == 0:
        siemplify.LOGGER.info(f"Could not find results for {url}")
        return results
    results = response["results"]
    total = response["total"]
    num_pages = math.ceil(total / int(response["pagination"]["pageSize"]))
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_pages) as executor:
        futures = []
        while len(results) < total and errors_on_pagination < max_allowed_errors_for_pagination:
            payload["pagination"]["pageNumber"] += 1
            siemplify.LOGGER.info(f"Doing pagination {payload['pagination']['pageNumber']} for {url}")
            futures.append(executor.submit(execute_logzio_api_call, siemplify, api_token, json.dumps(payload), url))
        for future in concurrent.futures.as_completed(futures):
            response = future.result()
            if response is None or len(response["results"]) == 0:
                siemplify.LOGGER.error("Error in pagination procedure. Skipping to next page, if exists.")
                errors_on_pagination += 1
                continue
            results += response["results"]
    return results


def execute_logzio_api_call(siemplify, api_token, payload, url):
    """ Communicates with the Logz.io API and returnes the response """
    headers = {
        'Content-Type': 'application/json',
        'X-API-TOKEN': api_token
    }

    try:
        response = requests.post(url, headers=headers, data=payload, timeout=5)
        siemplify.LOGGER.info("Status code from Logz.io: {}".format(response.status_code))
        if response.status_code == 200:
            response = json.loads(response.content)
            return response
        else:
            siemplify.LOGGER.error("API request returned {}:\n{}".format(response.status_code, response.text))
            return None
    except Exception as e:
        siemplify.LOGGER.error("Error occurred while calling Logz.io API:\n{}".format(e))
        return None


def get_unicode(unicode_unicode):
    return str(unicode_unicode)


def dict_to_flat(target_dict):
    """
    Receives nested dictionary and returns it as a flat dictionary.
    :param target_dict: {dict}
    :return: Flat dict : {dict}
    """
    target_dict = copy.deepcopy(target_dict)

    def expand(raw_key, raw_value):
        key = raw_key
        value = raw_value
        """
        :param key: {string}
        :param value: {string}
        :return: Recursive function.
        """
        if value is None:
            return [(get_unicode(key), u"")]
        elif isinstance(value, dict):
            # Handle dict type value
            return [(u"{0}_{1}".format(get_unicode(key),
                                       get_unicode(sub_key)),
                     get_unicode(sub_value)) for sub_key, sub_value in dict_to_flat(value).items()]
        elif isinstance(value, list):
            # Handle list type value
            count = 1
            l = []
            items_to_remove = []
            for value_item in value:
                if isinstance(value_item, dict):
                    # Handle nested dict in list
                    l.extend([(u"{0}_{1}_{2}".format(get_unicode(key),
                                                     get_unicode(count),
                                                     get_unicode(sub_key)),
                               sub_value)
                              for sub_key, sub_value in dict_to_flat(value_item).items()])
                    items_to_remove.append(value_item)
                    count += 1
                elif isinstance(value_item, list):
                    l.extend(expand(get_unicode(key) + u'_' + get_unicode(count), value_item))
                    count += 1
                    items_to_remove.append(value_item)

            for value_item in items_to_remove:
                value.remove(value_item)

            for value_item in value:
                l.extend([(get_unicode(key) + u'_' + get_unicode(count), value_item)])
                count += 1

            return l
        else:
            return [(get_unicode(key), get_unicode(value))]

    items = [item for sub_key, sub_value in target_dict.items() for item in
             expand(sub_key, sub_value)]
    return dict(items)


if __name__ == "__main__":
    main()
