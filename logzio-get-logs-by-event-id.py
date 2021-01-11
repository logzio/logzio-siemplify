from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED,EXECUTION_STATE_TIMEDOUT


import requests


DEFAULT_PAGE_SIZE = 25
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 1000

@output_handler
def main():
    siemplify = SiemplifyAction()

    logzio_token = siemplify.extract_configuration_param('Logzio',"logzio_token", default_value="-", is_mandatory=True)
    if logzio_token == "-" or logzio_token == "":
        siemplify.LOGGER.error("Error occurred: no Logzio API token! Exiting.")
        raise ValueError
    logzio_region = siemplify.extract_configuration_param('Logzio',"logzio_region", default_value="")
    logs_response = execute_logzio_api(siemplify, logzio_token, logzio_region)

    # status = EXECUTION_STATE_COMPLETED  # used to flag back to siemplify system, the action final status
    # output_message = "output message :"  # human readable message, showed in UI as the action result
    # result_value = None  # Set a simple result value, used for playbook if\else and placeholders.


    # for entity in siemplify.target_entities:
    #     print(entity.identifier)



    # siemplify.LOGGER.info("\n  status: {}\n  result_value: {}\n  output_message: {}".format(status,result_value, output_message))
    # siemplify.end(output_message, result_value, status)
    
    
def execute_logzio_api(siemplify, api_token, logzio_region, page_number=1):
    """ Sends request to Logz.io and returnes the response, if applicable """
    try:
        siemplify.LOGGER.info("Fetching page number {}".format(page_number))
        new_request = create_request_body_obj(siemplify, page_number)
        new_events = fetch_security_events(api_token, new_request, logzio_region, siemplify)
        if new_events != None:
            return new_events
    except Exception as e:
        siemplify.LOGGER.error("Error occurred while fetching events from page {}: {}".format(page_number, e))
    return None


def create_request_body_obj(siemplify, page_number=1):
    """ Creates request to send to Logz.io API """
    alert_event_id = siemplify.extract_action_param("alert_event_id", default_value="", is_mandatory=True, print_value=True)
    if alert_event_id == "":
        siemplify.LOGGER.error("Error occurred: no alert_event_id! Exiting.")
        raise ValueError
    request_body = {}
    page_size = siemplify.extract_action_param("page_size", is_mandatory=False, default_value=DEFAULT_PAGE_SIZE, input_type=int)
    if page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE:
        siemplify.LOGGER.warn("Invalid page size. Should be betwwen {} and {}. Reverting to default page size: {}".format(MIN_PAGE_SIZE, MAX_PAGE_SIZE, DEFAULT_PAGE_SIZE))
        page_size = DEFAULT_PAGE_SIZE
    request_body["filter"] = {}
    request_body["filter"]["alertEventId"] = alertEventId
    request_body["pagination"] = dict(pageNumber=page_number, pageSize=page_size)
    return request_body
    

if __name__ == "__main__":
    main()
