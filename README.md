# ServiceNow MCP Server

[![smithery badge](https://smithery.ai/badge/@michaelbuckner/servicenow-mcp)](https://smithery.ai/server/@michaelbuckner/servicenow-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server that interfaces with ServiceNow, allowing AI agents to access and manipulate ServiceNow data through a secure API. This server enables natural language interactions with ServiceNow, making it easier to search for records, update them, and manage scripts.

## Features

### Resources

- `servicenow://incidents`: List recent incidents
- `servicenow://incidents/{number}`: Get a specific incident by number
- `servicenow://users`: List users
- `servicenow://knowledge`: List knowledge articles
- `servicenow://tables`: List available tables
- `servicenow://tables/{table}`: Get records from a specific table
- `servicenow://schema/{table}`: Get the schema for a table

### Tools

#### Basic Tools
- `create_incident`: Create a new incident
- `update_incident`: Update an existing incident
- `search_records`: Search for records using text query
- `get_record`: Get a specific record by sys_id
- `perform_query`: Perform a query against ServiceNow
- `add_comment`: Add a comment to an incident (customer visible)
- `add_work_notes`: Add work notes to an incident (internal)

#### Natural Language Tools
- `natural_language_search`: Search for records using natural language (e.g., "find all incidents about SAP")
- `natural_language_update`: Update records using natural language (e.g., "Update incident INC0010001 saying I'm working on it")
- `update_script`: Update ServiceNow script files (script includes, business rules, etc.)

## Installation

### Installing via Smithery

To install ServiceNow MCP Server for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@michaelbuckner/servicenow-mcp):

```bash
npx -y @smithery/cli install @michaelbuckner/servicenow-mcp --client claude
```

### From PyPI

```bash
pip install mcp-server-servicenow
```

### From Source

```bash
git clone https://github.com/michaelbuckner/servicenow-mcp.git
cd servicenow-mcp
pip install -e .
```

## Usage

### Command Line

Run the server using the Python module:

```bash
python -m mcp_server_servicenow.cli --url "https://your-instance.service-now.com/" --username "your-username" --password "your-password"
```

Or use environment variables:

```bash
export SERVICENOW_INSTANCE_URL="https://your-instance.service-now.com/"
export SERVICENOW_USERNAME="your-username"
export SERVICENOW_PASSWORD="your-password"
python -m mcp_server_servicenow.cli
```

### Configuration in Cline

To use this MCP server with Cline, add the following to your MCP settings file:

```json
{
  "mcpServers": {
    "servicenow": {
      "command": "/path/to/your/python/executable",
      "args": [
        "-m",
        "mcp_server_servicenow.cli",
        "--url", "https://your-instance.service-now.com/",
        "--username", "your-username",
        "--password", "your-password"
      ],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

**Note:** Make sure to use the full path to the Python executable that has the `mcp-server-servicenow` package installed.

## Natural Language Examples

### Searching Records

You can search for records using natural language queries:

```
find all incidents about email
search for incidents related to network issues
show me all incidents with high priority
```

### Updating Records

You can update records using natural language commands:

```
Update incident INC0010001 saying I'm working on it
Set incident INC0010002 to in progress
Close incident INC0010003 with resolution: fixed the issue
```

### Managing Scripts

You can update ServiceNow scripts from local files:

```
Update the ServiceNow script include "HelloWorld" with the contents of hello_world.js
Upload utils.js to ServiceNow as a script include named "UtilityFunctions"
Update @form_validation.js, it's a client script called "FormValidation"
```

## Authentication Methods

The server supports multiple authentication methods:

1. **Basic Authentication**: Username and password
2. **Token Authentication**: OAuth token
3. **OAuth Authentication**: Client ID, Client Secret, Username, and Password

## Development

### Prerequisites

- Python 3.8+
- ServiceNow instance with API access

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/michaelbuckner/servicenow-mcp.git
cd servicenow-mcp

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
