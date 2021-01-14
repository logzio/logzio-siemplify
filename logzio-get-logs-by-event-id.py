from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT

import concurrent.futures
import json
import math
import requests

BASE_URL = "https://api.logz.io/"
SEARCH_LOGS_API_SUFFIX = "v2/security/rules/events/logs/search"
DEFAULT_PAGE_SIZE = 25
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 1000

@output_handler
def main():
    siemplify = SiemplifyAction()
    status = EXECUTION_STATE_FAILED # default. will be changed only if logs retrieved and parsed to json successfully.
    num_logs = 0
    logzio_token = siemplify.extract_configuration_param('Logzio',"logzio_token", default_value="-", is_mandatory=True)
    if logzio_token == "-" or logzio_token == "":
        siemplify.LOGGER.error("Error occurred: no Logzio API token! Exiting.")
        raise ValueError
    logzio_region = siemplify.extract_configuration_param('Logzio',"logzio_region", default_value="")
    logs_response = execute_logzio_api(siemplify, logzio_token, logzio_region)
    if logs_response is not None:
        logs_json, num_logs = create_json_result(siemplify, logs_response, logzio_token, logzio_region)
        if logs_json is not None:
            siemplify.result.add_result_json(logs_json)
            status = EXECUTION_STATE_COMPLETED
    
    output_message = get_output_msg(status, num_logs)
    is_success = status == EXECUTION_STATE_COMPLETED
    siemplify.end(output_message, is_success, status)
    
    
    
def execute_logzio_api(siemplify, api_token, logzio_region, page_number=1):
    """ Sends request to Logz.io and returnes the response, if applicable """
    alert_event_id = siemplify.extract_action_param("alert_event_id", default_value="", is_mandatory=True, print_value=True)
    if alert_event_id == "":
        siemplify.LOGGER.error("Error occurred: no alert_event_id! Exiting.")
        raise ValueError
    try:
        siemplify.LOGGER.info("Fetching page number {}".format(page_number))
        new_request = create_request_body_obj(siemplify, alert_event_id, page_number)
        new_logs = fetch_logs_by_event_id(api_token, new_request, logzio_region, siemplify, alert_event_id)
        if new_logs != None:
            return new_logs
    except Exception as e:
        siemplify.LOGGER.error("Error occurred while fetching events from page {}: {}".format(page_number, e))
    return None


def create_request_body_obj(siemplify, alert_event_id, page_number=1):
    """ Creates request to send to Logz.io API """
    request_body = {}
    page_size = siemplify.extract_action_param("page_size", is_mandatory=False, default_value=DEFAULT_PAGE_SIZE, input_type=int)
    if page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE:
        siemplify.LOGGER.warn("Invalid page size. Should be betwwen {} and {}. Reverting to default page size: {}".format(MIN_PAGE_SIZE, MAX_PAGE_SIZE, DEFAULT_PAGE_SIZE))
        page_size = DEFAULT_PAGE_SIZE
    request_body["filter"] = {}
    request_body["filter"]["alertEventId"] = alert_event_id
    request_body["pagination"] = dict(pageNumber=page_number, pageSize=page_size)
    return request_body
    
    
def fetch_logs_by_event_id(api_token, req_body, region, siemplify, alert_event_id):
    """
    Returnes from Logz.io all the logs that triggered the event.
    If error occured or no results found, returnes None
    """
    headers = {
        'Content-Type': 'application/json',
        'X-API-TOKEN': api_token
    }

    url = get_base_api_url(region) + SEARCH_LOGS_API_SUFFIX
    siemplify.LOGGER.info("api url: {}".format(url))
    try:
        body = json.dumps(req_body)
        siemplify.LOGGER.info("Fetching logs that triggered event {} from Logz.io".format(alert_event_id))
        response = requests.post(url, headers=headers, data=body, timeout=5)
        siemplify.LOGGER.info("Status code from Logz.io: {}".format(response.status_code))
        if response.status_code == 200:
            logs_response = json.loads(response.content)
            if logs_response["total"] > 0:
                return logs_response
            siemplify.LOGGER.warn("No resultes found to match your request")
            return None
        else:
            siemplify.LOGGER.error("API request returned {}".format(response.status_code))
    except Exception as e:
        siemplify.LOGGER.error("Error occurred while fetching logs that triggered event {} from Logz.io:\n{}".format(alert_event_id, e))
        return None
        

def get_base_api_url(region):
    """ Returnes API url, in accordance to user's input """
    if region == "us" or region == "" or region == "-":
        return BASE_URL
    else:
        return BASE_URL.replace("api.", "api-{}.".format(region))


def create_json_result(siemplify, logs_response, logzio_token, logzio_region):
    collected_logs = collect_all_logs(siemplify, logs_response, logzio_token, logzio_token)
    if collected_logs is not None and len(collected_logs) > 0:
        return json.dumps(collected_logs), len(collected_logs)
    return None


def collect_all_logs(siemplify, logs_response, api_token, logzio_region):
    collected_logs = logs_response["results"]
    num_collected_logs = len(collected_logs)
    total_results_available = int(logs_response["total"])
    current_page = int(logs_response["pagination"]["pageNumber"])
    num_pages = math.ceil(total_results_available/int(logs_response["pagination"]["pageSize"]))
    siemplify.LOGGER.info("Request retrieved {} logs from Logz.io".format(num_collected_logs))
    siemplify.LOGGER.info("There are {} logs in your Logz.io account that match your alert-event-id".format(total_results_available))
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_pages) as executor:
        futures = []
        while num_pages > current_page:
            current_page += 1
            print("fetching page: {}".format(current_page))
            futures.append(executor.submit(execute_logzio_api, siemplify, api_token, logzio_region, current_page))
        for future in concurrent.futures.as_completed(futures):
            new_log = future.result()
            if new_log is not None:
                collected_logs += new_log["results"]
                num_collected_logs += len(new_log["results"])
                siemplify.LOGGER.info("Fetched {} events".format(len(new_log["results"])))
        
        if total_results_available != num_collected_logs:
            siemplify.LOGGER.warn("Retrieved {} events out of {} available events. Only the retrieved events will be injected to Siemplify".format(num_collected_events, total_results_available))
    siemplify.LOGGER.info("Total collected: {}".format(len(collected_logs)))
    return collected_logs


def get_output_msg(status, num_logs):
    if status == EXECUTION_STATE_COMPLETED:
        return "Retrieved successfully {} logs that triggered the alert".format(num_logs)
    else:
        return "Failed to retrieve logs. Please check the script's logs to see what went wrong..."
    
    
if __name__ == "__main__":
    main()
