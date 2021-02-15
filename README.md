# logzio-siemplify

### `connector-fetch-security-events.py`:
**Input:**
- **logzio_token**: (mandatory) Logzio security API token.
- **from_date**: (mandatory) Start time to search security events.
Can be either in Unix time format, or in the format "%Y-%m-%d %H:%M:%S.%f". Will only be applicable for the connector's first run.
- **logzio_region**: Your Logzio's account region. Can be left empty for US region.
- **logzio_custom_endpoint**: Custom endpoint for Logz.io API. Will override the logzio_region param.
- **page_size**: Controls the number of results per page. Valid inputs are 1 to 1000. Defaults to 25.
- **search_term**: Filter for a matching string in the security rule name.
- **severities**: A comma-delimited list of security rules severities: "INFO", "LOW", "MEDIUM", "HIGH", "SEVERE".

**Output:**
Returns events that match the query, in the format that the API returns.

This connector creates a request to the search events API, and sends it.
When the response from the API received, it collects all the available logs, meaning that if there are more available results than the page size, it will use the pagination mechanism of the API and will send more requests with python futures, until all the available logs are retrieved.
It saves the latest timestamp (max between latest log timestamp and 1 hour ago) to be the next timestamp to pull logs from.

### `logzio-get-logs-by-event-id.py`:
**Input:**
- **alert_event_id**: (mandatory) event id you'd like to search logs for.
- **page_size**: Controls the number of results per page. Valid inputs are 1 to 1000. Defaults to 25.

**Output:**
Returns logs that triggered the event, in the format that the API returns.

This action creates a request to the search logs by event id API, and sends it.
When the response from the API received, it collects all the available logs, meaning that if there are more available results than the page size, it will use the pagination mechanism of the API and will send more requests with python futures, until all the available logs are retrieved.
It adds the results as insights, and returns the json.

### `logzio-search-logs.py`:
**Input:**
- **query**: The search query. Defaults to `*`.
- **size**: Maximum amount of logs you'd like the query to return. Limited to 1000 logs.
- **from_time**: Start time to search.
- **to_time**: End time to search.

**Output:**
Returns logs that match the query in the following format:
```shell
{
	"results": [
		{
			#log
		},
		....
		{
			#log
		}
	]
}
```

### `json-adapter.py`:
**Input:**
- **fields_to_search**: The fields you want to search in the json.
- **raw_json**: The json to search in.
The raw json shoule be in the following format:
```shell
{
	"results": [
		{
			#log
		},
		....
		{
			#log
		}
	]
}
```

**Output**:
New json in the following format:
```shell
{
    "results": [
        { 
            "entityType": "field_from_json",
            "entityIdentifier": "value_from_json"
        },
        .....
    ]
}
```

This action searches for the fields in the json and returns it in the format above, to match Siemplify system.

### `ping.py`:
This action validates the integrations inputs.
It sends requests to the whoami API to validate the API and the tokens. For testing only.


### General integration inputs:
General inputs applies only for the actions. Connector has it's own params.
- logzio_operation_token - mendatory
- logzio_security_token - mendatory
- logzio_region
- logzio_custom_endpoint