from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

import json

"""
This adapter is suitable for jsons in the following format:
{
    "results": [
        { 
            "key1": "x",
            "key2": "y"
        },
        .....
    ]
}
"""

@output_handler
def main():
    siemplify = SiemplifyAction()

    search_fields = siemplify.extract_action_param("fields_to_search")
    raw_json = siemplify.extract_action_param("raw_json")
    output = []
    status = EXECUTION_STATE_FAILED # default value. Will considered success only if found values
    is_success = False
    
    try:
        fields = [f.strip() for f in search_fields.split(",")]
        json_obj = json.loads(raw_json)
        siemplify.LOGGER.info("Retrieved fields to search and json")
        
        if fields is not None and len(fields) > 0 and json_obj is not None and len(json_obj) > 0:
            for result in json_obj["results"]:
                for field in fields:
                    siemplify.LOGGER.info("Searching field: {}".format(field))
                    if field in result:
                        output.append({field: result[field]})
                    else:
                        siemplify.LOGGER.info("Couldn't find field {} in given json".format(field))
        
        siemplify.LOGGER.info("Found {} out of given {} fields".format(len(output), len(fields)))
        
        if len(output) > 0:
            output_json = json.dumps(output)
            siemplify.result.add_result_json(output_json)
            status = EXECUTION_STATE_COMPLETED
            is_success = True
            
    except Exception as e:
        siemplify.LOGGER.error("Error occurred while searching fields in json: {}\n Exiting json adapter".format(e))
        
    output_message = get_output_by_status(status)
    siemplify.end(output_message, is_success, status)


def get_output_by_status(status):
    if status == EXECUTION_STATE_COMPLETED:
        return "Json adapter script finished successfully with results"
    else:
        return "Json adapter script could not filter json"


if __name__ == "__main__":
    main()
