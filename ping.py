from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

import requests
import os


BASE_URL = "api.logz.io"

@output_handler
def main():
    siemplify = SiemplifyAction()
    status = EXECUTION_STATE_FAILED
    is_success = False
    security_token = siemplify.extract_configuration_param('Logzio',"logzio_security_token", default_value="-", is_mandatory=True)
    operations_token = siemplify.extract_configuration_param('Logzio',"logzio_operations_token", default_value="-", is_mandatory=True)
    logzio_region = siemplify.extract_configuration_param('Logzio',"logzio_region", default_value="")
    
    try:
        validate_token(siemplify, security_token)
        validate_token(siemplify, operations_token)
        ping_api(siemplify, logzio_region)
        status = EXECUTION_STATE_COMPLETED
        is_success = True
    except Exception as e:
        siemplify.LOGGER.error("Error occurred. {}".format(e))
        
    output_message = create_output_msg(status)
    siemplify.end(output_message, is_success, status)
    
    
def validate_token(siemplify, token):
    if token is None or token == "-" or token == "":
        raise ValueError("Must insert Logzio operations & security tokens")
    if type(token) is not str:
        raise TypeError("Logzio tokens must be strings")
    siemplify.LOGGER.info("Valid token: {}".format(token))
    return True



def ping_api(siemplify, logzio_region):
    url = get_base_api_url(logzio_region)
    response = os.system("ping -c 1 " + url)
    if response == 0:
        siemplify.LOGGER.info("ping to {} successful".format(url))
        return True
    else:
        raise ConnectionError("Ping to {} unsuccessful".format(url))
    

def get_base_api_url(region):
    """ Returnes API url, in accordance to user's input """
    if region == "us" or region == "" or region == "-":
        return BASE_URL
    else:
        return BASE_URL.replace("api.", "api-{}.".format(region))


def create_output_msg(status):
    if status == EXECUTION_STATE_COMPLETED:
        return "Tokens are valid, ping successful."
    else:
        return "Error occurred while trying to validate tokens or ping Logz.io API"

if __name__ == "__main__":
    main()
