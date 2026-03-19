"""
ServiceNow MCP Server

This module provides a Model Context Protocol (MCP) server that interfaces with ServiceNow.
It allows AI agents to access and manipulate ServiceNow data through a secure API.
"""

import os
import json
import asyncio
import logging
import re
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union, Literal, Tuple

import requests
import httpx
from pydantic import BaseModel, Field, field_validator

from mcp_server_servicenow.nlp import NLPProcessor

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)

# ServiceNow API models
class IncidentState(int, Enum):
    NEW = 1
    IN_PROGRESS = 2 
    ON_HOLD = 3
    RESOLVED = 6
    CLOSED = 7
    CANCELED = 8

class IncidentPriority(int, Enum):
    CRITICAL = 1
    HIGH = 2
    MODERATE = 3
    LOW = 4
    PLANNING = 5

class IncidentUrgency(int, Enum):
    HIGH = 1
    MEDIUM = 2
    LOW = 3

class IncidentImpact(int, Enum):
    HIGH = 1
    MEDIUM = 2
    LOW = 3

class IncidentCreate(BaseModel):
    """Model for creating a new incident"""
    short_description: str = Field(..., description="A brief description of the incident")
    description: str = Field(..., description="A detailed description of the incident")
    caller_id: Optional[str] = Field(None, description="The sys_id or name of the caller")
    category: Optional[str] = Field(None, description="The incident category")
    subcategory: Optional[str] = Field(None, description="The incident subcategory")
    urgency: Optional[IncidentUrgency] = Field(IncidentUrgency.MEDIUM, description="The urgency of the incident")
    impact: Optional[IncidentImpact] = Field(IncidentImpact.MEDIUM, description="The impact of the incident")
    assignment_group: Optional[str] = Field(None, description="The sys_id or name of the assignment group")
    assigned_to: Optional[str] = Field(None, description="The sys_id or name of the assignee")

class IncidentUpdate(BaseModel):
    """Model for updating an existing incident"""
    short_description: Optional[str] = Field(None, description="A brief description of the incident")
    description: Optional[str] = Field(None, description="A detailed description of the incident")
    caller_id: Optional[str] = Field(None, description="The sys_id or name of the caller")
    category: Optional[str] = Field(None, description="The incident category")
    subcategory: Optional[str] = Field(None, description="The incident subcategory")
    urgency: Optional[IncidentUrgency] = Field(None, description="The urgency of the incident")
    impact: Optional[IncidentImpact] = Field(None, description="The impact of the incident")
    state: Optional[IncidentState] = Field(None, description="The state of the incident")
    assignment_group: Optional[str] = Field(None, description="The sys_id or name of the assignment group")
    assigned_to: Optional[str] = Field(None, description="The sys_id or name of the assignee")
    work_notes: Optional[str] = Field(None, description="Work notes to add to the incident (internal)")
    comments: Optional[str] = Field(None, description="Customer visible comments to add to the incident")
    
    @field_validator('work_notes', 'comments')
    @classmethod
    def validate_not_empty(cls, v):
        if v is not None and v.strip() == '':
            raise ValueError("Cannot be an empty string")
        return v

    class Config:
        use_enum_values = True
        
class QueryOptions(BaseModel):
    """Options for querying ServiceNow records"""
    limit: int = Field(10, description="Maximum number of records to return", ge=1, le=1000)
    offset: int = Field(0, description="Number of records to skip", ge=0)
    fields: Optional[List[str]] = Field(None, description="List of fields to return")
    query: Optional[str] = Field(None, description="ServiceNow encoded query string")
    order_by: Optional[str] = Field(None, description="Field to order results by")
    order_direction: Optional[Literal["asc", "desc"]] = Field("desc", description="Order direction")

class Authentication:
    """Base class for ServiceNow authentication methods"""
    
    async def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for ServiceNow API requests"""
        raise NotImplementedError("Subclasses must implement this method")

class BasicAuth(Authentication):
    """Basic authentication for ServiceNow"""
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        
    async def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for ServiceNow API requests"""
        return {}
    
    def get_auth(self) -> tuple:
        """Get authentication tuple for requests"""
        return (self.username, self.password)

class TokenAuth(Authentication):
    """Token authentication for ServiceNow"""
    
    def __init__(self, token: str):
        self.token = token
        
    async def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for ServiceNow API requests"""
        return {"Authorization": f"Bearer {self.token}"}
    
    def get_auth(self) -> None:
        """Get authentication tuple for requests"""
        return None

class OAuthAuth(Authentication):
    """OAuth authentication for ServiceNow"""
    
    def __init__(self, client_id: str, client_secret: str, username: str, password: str, 
                 instance_url: str, token: Optional[str] = None, refresh_token: Optional[str] = None,
                 token_expiry: Optional[datetime] = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.instance_url = instance_url
        self.token = token
        self.refresh_token = refresh_token
        self.token_expiry = token_expiry
        
    async def get_headers(self) -> Dict[str, str]:
        """Get authentication headers for ServiceNow API requests"""
        if self.token is None or (self.token_expiry and datetime.now().timestamp() > self.token_expiry):
            await self.refresh()
            
        return {"Authorization": f"Bearer {self.token}"}
    
    def get_auth(self) -> None:
        """Get authentication tuple for requests"""
        return None
        
    async def refresh(self):
        """Refresh the OAuth token"""
        if self.refresh_token:
            # Try refresh flow first
            data = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token
            }
        else:
            # Fall back to password flow
            data = {
                "grant_type": "password",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "username": self.username,
                "password": self.password
            }
            
        token_url = f"{self.instance_url}/oauth_token.do"
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            result = response.json()
            
            self.token = result["access_token"]
            self.refresh_token = result.get("refresh_token")
            expires_in = result.get("expires_in", 1800)  # Default 30 minutes
            self.token_expiry = datetime.now().timestamp() + expires_in

class ServiceNowClient:
    """Client for interacting with ServiceNow API"""
    
    def __init__(self, instance_url: str, auth: Authentication):
        self.instance_url = instance_url.rstrip('/')
        self.auth = auth
        self.client = httpx.AsyncClient()
        
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
        
    async def request(self, method: str, path: str, 
                    params: Optional[Dict[str, Any]] = None,
                    json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a request to the ServiceNow API"""
        url = f"{self.instance_url}{path}"
        headers = await self.auth.get_headers()
        headers["Accept"] = "application/json"
        
        if isinstance(self.auth, BasicAuth):
            auth = self.auth.get_auth()
        else:
            auth = None
            
        try:
            response = await self.client.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=headers,
                auth=auth
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"ServiceNow API error: {e.response.text}")
            raise
            
    async def get_record(self, table: str, sys_id: str) -> Dict[str, Any]:
        """Get a record by sys_id"""
        if table == "incident" and sys_id.startswith("INC"):
            # This is an incident number, not a sys_id
            logger.warning(f"Attempted to use get_record with incident number instead of sys_id: {sys_id}")
            logger.warning("Redirecting to get_incident_by_number method")
            result = await self.get_incident_by_number(sys_id)
            if result:
                return {"result": result}
            else:
                raise ValueError(f"Incident not found: {sys_id}")
        return await self.request("GET", f"/api/now/table/{table}/{sys_id}")
        
    async def get_records(self, table: str, options: QueryOptions = None) -> Dict[str, Any]:
        """Get records with query options"""
        if options is None:
            options = QueryOptions()
            
        params = {
            "sysparm_limit": options.limit,
            "sysparm_offset": options.offset
        }
        
        if options.fields:
            params["sysparm_fields"] = ",".join(options.fields)
            
        if options.query:
            params["sysparm_query"] = options.query
            
        if options.order_by:
            direction = "desc" if options.order_direction == "desc" else "asc"
            params["sysparm_order_by"] = f"{options.order_by}^{direction}"
            
        return await self.request("GET", f"/api/now/table/{table}", params=params)
    
    async def create_record(self, table: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new record"""
        return await self.request("POST", f"/api/now/table/{table}", json_data=data)
        
    async def update_record(self, table: str, sys_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing record"""
        return await self.request("PUT", f"/api/now/table/{table}/{sys_id}", json_data=data)
        
    async def delete_record(self, table: str, sys_id: str) -> Dict[str, Any]:
        """Delete a record"""
        return await self.request("DELETE", f"/api/now/table/{table}/{sys_id}")
        
    async def get_incident_by_number(self, number: str) -> Dict[str, Any]:
        """Get an incident by its number"""
        result = await self.request("GET", f"/api/now/table/incident", 
                                  params={"sysparm_query": f"number={number}", "sysparm_limit": 1})
        if result.get("result") and len(result["result"]) > 0:
            return result["result"][0]
        return None
        
    async def search(self, query: str, table: str = "incident", limit: int = 10) -> Dict[str, Any]:
        """Search for records using text query"""
        return await self.request("GET", f"/api/now/table/{table}", 
                                params={"sysparm_query": f"123TEXTQUERY321={query}", "sysparm_limit": limit})
                                
    async def get_available_tables(self) -> List[str]:
        """Get a list of available tables"""
        result = await self.request("GET", "/api/now/table/sys_db_object", 
                                  params={"sysparm_fields": "name,label", "sysparm_limit": 100})
        return result.get("result", [])
        
    async def get_table_schema(self, table: str) -> Dict[str, Any]:
        """Get the schema for a table"""
        result = await self.request("GET", f"/api/now/ui/meta/{table}")
        return result


class ScriptUpdateModel(BaseModel):
    """Model for updating a ServiceNow script"""
    name: str = Field(..., description="The name of the script")
    script: str = Field(..., description="The script content")
    type: str = Field(..., description="The type of script (e.g., sys_script_include)")
    description: Optional[str] = Field(None, description="Description of the script")

class ServiceNowMCP:
    """ServiceNow MCP Server"""
    
    def __init__(self, 
                instance_url: str,
                auth: Authentication,
                name: str = "ServiceNow MCP"):
        self.client = ServiceNowClient(instance_url, auth)
        self.mcp = FastMCP(name, dependencies=[
            "requests",
            "httpx", 
            "pydantic"
        ])
        
        # Register resources
        self.mcp.resource("servicenow://incidents")(self.list_incidents)
        self.mcp.resource("servicenow://incidents/{number}")(self.get_incident)
        self.mcp.resource("servicenow://users")(self.list_users)
        self.mcp.resource("servicenow://knowledge")(self.list_knowledge)
        self.mcp.resource("servicenow://tables")(self.get_tables)
        self.mcp.resource("servicenow://tables/{table}")(self.get_table_records)
        self.mcp.resource("servicenow://schema/{table}")(self.get_table_schema)
        
        # Register tools
        self.mcp.tool(name="create_incident")(self.create_incident)
        self.mcp.tool(name="update_incident")(self.update_incident)
        self.mcp.tool(name="search_records")(self.search_records)
        self.mcp.tool(name="get_record")(self.get_record)
        self.mcp.tool(name="perform_query")(self.perform_query)
        self.mcp.tool(name="add_comment")(self.add_comment)
        self.mcp.tool(name="add_work_notes")(self.add_work_notes)
        
        # Register natural language tools
        self.mcp.tool(name="natural_language_search")(self.natural_language_search)
        self.mcp.tool(name="natural_language_update")(self.natural_language_update)
        self.mcp.tool(name="update_script")(self.update_script)
        
        # Register prompts
        self.mcp.prompt(name="analyze_incident")(self.incident_analysis_prompt)
        self.mcp.prompt(name="create_incident_prompt")(self.create_incident_prompt)
    
    async def close(self):
        """Close the ServiceNow client"""
        await self.client.close()
        
    def run(self, transport: str = "stdio"):
        """Run the ServiceNow MCP server"""
        try:
            self.mcp.run(transport=transport)
        finally:
            asyncio.run(self.close())
        
    # Resource handlers
    async def list_incidents(self) -> str:
        """List recent incidents in ServiceNow"""
        options = QueryOptions(limit=10)
        result = await self.client.get_records("incident", options)
        return json.dumps(result, indent=2)
        
    async def get_incident(self, number: str) -> str:
        """Get a specific incident by number"""
        try:
            # Always use get_incident_by_number to query by incident number, not get_record
            incident = await self.client.get_incident_by_number(number)
            if incident:
                return json.dumps({"result": incident}, indent=2)
            else:
                logger.error(f"No incident found with number: {number}")
                return json.dumps({"error":{"message":"No Record found","detail":"Record doesn't exist or ACL restricts the record retrieval"},"status":"failure"})
        except Exception as e:
            logger.error(f"Error getting incident {number}: {str(e)}")
            return json.dumps({"error":{"message":str(e),"detail":"Error occurred while retrieving the record"},"status":"failure"})
        
    async def list_users(self) -> str:
        """List users in ServiceNow"""
        options = QueryOptions(limit=10)
        result = await self.client.get_records("sys_user", options)
        return json.dumps(result, indent=2)
        
    async def list_knowledge(self) -> str:
        """List knowledge articles in ServiceNow"""
        options = QueryOptions(limit=10)
        result = await self.client.get_records("kb_knowledge", options)
        return json.dumps(result, indent=2)
        
    async def get_tables(self) -> str:
        """Get a list of available tables"""
        result = await self.client.get_available_tables()
        return json.dumps({"result": result}, indent=2)
        
    async def get_table_records(self, table: str) -> str:
        """Get records from a specific table"""
        options = QueryOptions(limit=10)
        result = await self.client.get_records(table, options)
        return json.dumps(result, indent=2)
        
    async def get_table_schema(self, table: str) -> str:
        """Get the schema for a table"""
        result = await self.client.get_table_schema(table)
        return json.dumps(result, indent=2)
    
    # Tool handlers
    async def create_incident(self, 
                     incident,
                     ctx: Context = None) -> str:
        """
        Create a new incident in ServiceNow
        
        Args:
            incident: The incident details to create - can be either an IncidentCreate object,
                      a dictionary containing incident fields, or a string with the description
            ctx: Optional context object for progress reporting
        
        Returns:
            JSON response from ServiceNow
        """
        # Handle different input types
        if isinstance(incident, str):
            # If a string was provided, treat it as the description and generate a short description
            short_desc = incident[:50] + ('...' if len(incident) > 50 else '')
            incident_data = {
                "short_description": short_desc,
                "description": incident
            }
            logger.info(f"Creating incident from string description: {short_desc}")
        elif isinstance(incident, dict):
            # Dictionary provided
            incident_data = incident
            logger.info(f"Creating incident from dictionary: {incident.get('short_description', 'No short description')}")
        elif isinstance(incident, IncidentCreate):
            # IncidentCreate model provided
            incident_data = incident.dict(exclude_none=True)
            logger.info(f"Creating incident from IncidentCreate: {incident.short_description}")
        else:
            error_message = f"Invalid incident type: {type(incident)}. Expected IncidentCreate, dict, or str."
            logger.error(error_message)
            return json.dumps({"error": error_message})

        # Validate that required fields are present
        if "short_description" not in incident_data and isinstance(incident, dict):
            if "description" in incident_data:
                # Auto-generate short description from description
                desc = incident_data["description"]
                incident_data["short_description"] = desc[:50] + ('...' if len(desc) > 50 else '')
            else:
                incident_data["short_description"] = "Incident created through API"
        
        if "description" not in incident_data and isinstance(incident, dict):
            if "short_description" in incident_data:
                incident_data["description"] = incident_data["short_description"]
            else:
                incident_data["description"] = "No description provided"
    
        # Log and create the incident
        if ctx:
            await ctx.info(f"Creating incident: {incident_data.get('short_description', 'No short description')}")
        
        try:
            result = await self.client.create_record("incident", incident_data)
            
            if ctx:
                await ctx.info(f"Created incident: {result['result']['number']}")
                
            return json.dumps(result, indent=2)
        except Exception as e:
            error_message = f"Error creating incident: {str(e)}"
            logger.error(error_message)
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})
        
    async def update_incident(self,
                     number: str,
                     updates: IncidentUpdate,
                     ctx: Context = None) -> str:
        """
        Update an existing incident in ServiceNow
        
        Args:
            number: The incident number (INC0010001)
            updates: The fields to update
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response from ServiceNow
        """
        # First, get the sys_id for the incident number
        if ctx:
            await ctx.info(f"Looking up incident: {number}")
            
        incident = await self.client.get_incident_by_number(number)
        
        if not incident:
            error_message = f"Incident {number} not found"
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})
            
        sys_id = incident['sys_id']
        
        # Now update the incident
        if ctx:
            await ctx.info(f"Updating incident: {number}")
            
        data = updates.dict(exclude_none=True)
        result = await self.client.update_record("incident", sys_id, data)
        
        return json.dumps(result, indent=2)
        
    async def search_records(self, 
                    query: str, 
                    table: str = "incident",
                    limit: int = 10,
                    ctx: Context = None) -> str:
        """
        Search for records in ServiceNow using text query
        
        Args:
            query: Text to search for
            table: Table to search in
            limit: Maximum number of results to return
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response containing matching records
        """
        if ctx:
            await ctx.info(f"Searching {table} for: {query}")
            
        result = await self.client.search(query, table, limit)
        return json.dumps(result, indent=2)
        
    async def get_record(self,
                table: str,
                sys_id: str,
                ctx: Context = None) -> str:
        """
        Get a specific record by sys_id
        
        Args:
            table: Table to query
            sys_id: System ID of the record
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response containing the record
        """
        if ctx:
            await ctx.info(f"Getting {table} record: {sys_id}")
            
        result = await self.client.get_record(table, sys_id)
        return json.dumps(result, indent=2)
        
    async def perform_query(self,
                   table: str,
                   query: str = "",
                   limit: int = 10,
                   offset: int = 0,
                   fields: Optional[List[str]] = None,
                   ctx: Context = None) -> str:
        """
        Perform a query against ServiceNow
        
        Args:
            table: Table to query
            query: Encoded query string (ServiceNow syntax)
            limit: Maximum number of results to return
            offset: Number of records to skip
            fields: List of fields to return (or all fields if None)
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response containing query results
        """
        if ctx:
            await ctx.info(f"Querying {table} with: {query}")
            
        options = QueryOptions(
            limit=limit,
            offset=offset,
            fields=fields,
            query=query
        )
        
        result = await self.client.get_records(table, options)
        return json.dumps(result, indent=2)
        
    async def add_comment(self,
                 number: str,
                 comment: str,
                 ctx: Context = None) -> str:
        """
        Add a comment to an incident (customer visible)
        
        Args:
            number: Incident number
            comment: Comment to add
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response from ServiceNow
        """
        if ctx:
            await ctx.info(f"Adding comment to incident: {number}")
            
        incident = await self.client.get_incident_by_number(number)
        
        if not incident:
            error_message = f"Incident {number} not found"
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})
            
        sys_id = incident['sys_id']
        
        # Add the comment
        update = {"comments": comment}
        result = await self.client.update_record("incident", sys_id, update)
        
        return json.dumps(result, indent=2)
        
    async def add_work_notes(self,
                    number: str,
                    work_notes: str,
                    ctx: Context = None) -> str:
        """
        Add work notes to an incident (internal)
        
        Args:
            number: Incident number
            work_notes: Work notes to add
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response from ServiceNow
        """
        if ctx:
            await ctx.info(f"Adding work notes to incident: {number}")
            
        incident = await self.client.get_incident_by_number(number)
        
        if not incident:
            error_message = f"Incident {number} not found"
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})
            
        sys_id = incident['sys_id']
        
        # Add the work notes
        update = {"work_notes": work_notes}
        result = await self.client.update_record("incident", sys_id, update)
        
        return json.dumps(result, indent=2)
    
    # Natural language tools
    async def natural_language_search(self,
                             query: str,
                             ctx: Context = None) -> str:
        """
        Search for records using natural language
        
        Examples:
        - "find all incidents about SAP"
        - "search for incidents related to email"
        - "show me all incidents with high priority"
        
        Args:
            query: Natural language query
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response containing matching records
        """
        if ctx:
            await ctx.info(f"Processing natural language query: {query}")
            
        # Parse the query
        search_params = NLPProcessor.parse_search_query(query)
        
        if ctx:
            await ctx.info(f"Searching {search_params['table']} with query: {search_params['query']}")
        
        # Perform the search
        options = QueryOptions(
            limit=search_params['limit'],
            query=search_params['query']
        )
        
        result = await self.client.get_records(search_params['table'], options)
        return json.dumps(result, indent=2)
    
    async def natural_language_update(self,
                              command: str,
                              ctx: Context = None) -> str:
        """
        Update a record using natural language
        
        Examples:
        - "Update incident INC0010001 saying I'm working on it"
        - "Set incident INC0010002 to in progress"
        - "Close incident INC0010003 with resolution: fixed the issue"
        
        Args:
            command: Natural language update command
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response from ServiceNow
        """
        if ctx:
            await ctx.info(f"Processing natural language update: {command}")
            
        try:
            # Parse the command
            record_number, updates = NLPProcessor.parse_update_command(command)
            
            if ctx:
                await ctx.info(f"Updating {record_number} with: {updates}")
            
            # Get the record
            if record_number.startswith("INC"):
                incident = await self.client.get_incident_by_number(record_number)
                if not incident:
                    error_message = f"Incident {record_number} not found"
                    if ctx:
                        await ctx.error(error_message)
                    return json.dumps({"error": error_message})
                
                sys_id = incident['sys_id']
                table = "incident"
            else:
                # Handle other record types if needed
                error_message = f"Record type not supported: {record_number}"
                if ctx:
                    await ctx.error(error_message)
                return json.dumps({"error": error_message})
            
            # Update the record
            result = await self.client.update_record(table, sys_id, updates)
            return json.dumps(result, indent=2)
            
        except ValueError as e:
            error_message = str(e)
            if ctx:
                await ctx.error(error_message)
            return json.dumps({"error": error_message})
    
    async def update_script(self,
                   script_update: ScriptUpdateModel,
                   ctx: Context = None) -> str:
        """
        Update a ServiceNow script
        
        Args:
            script_update: The script update details
            ctx: Optional context object for progress reporting
            
        Returns:
            JSON response from ServiceNow
        """
        if ctx:
            await ctx.info(f"Updating script: {script_update.name}")
            
        # Search for the script by name
        table = script_update.type
        query = f"name={script_update.name}"
        
        options = QueryOptions(
            limit=1,
            query=query
        )
        
        result = await self.client.get_records(table, options)
        
        if not result.get("result") or len(result["result"]) == 0:
            # Script doesn't exist, create it
            if ctx:
                await ctx.info(f"Script not found, creating new script: {script_update.name}")
                
            data = {
                "name": script_update.name,
                "script": script_update.script
            }
            
            if script_update.description:
                data["description"] = script_update.description
                
            result = await self.client.create_record(table, data)
        else:
            # Script exists, update it
            script = result["result"][0]
            sys_id = script["sys_id"]
            
            if ctx:
                await ctx.info(f"Updating existing script: {script_update.name} ({sys_id})")
                
            data = {
                "script": script_update.script
            }
            
            if script_update.description:
                data["description"] = script_update.description
                
            result = await self.client.update_record(table, sys_id, data)
            
        return json.dumps(result, indent=2)
    
    # Prompt templates
    def incident_analysis_prompt(self, incident_number: str) -> str:
        """Create a prompt to analyze a ServiceNow incident
        
        Args:
            incident_number: The incident number to analyze (e.g., INC0010001)
            
        Returns:
            Prompt text for analyzing the incident
        """
        return f"""
        Please analyze the following ServiceNow incident {incident_number}.
        
        First, call the appropriate tool to fetch the incident details using get_incident.
        
        Then, provide a comprehensive analysis with the following sections:
        
        1. Summary: A brief overview of the incident
        2. Impact Assessment: Analysis of the impact based on the severity, priority, and affected users
        3. Root Cause Analysis: Potential causes based on available information
        4. Resolution Recommendations: Suggested next steps to resolve the incident
        5. SLA Status: Whether the incident is at risk of breaching SLAs
        
        Use a professional and clear tone appropriate for IT service management.
        """
        
    def create_incident_prompt(self) -> str:
        """Create a prompt for incident creation guidance
        
        Returns:
            Prompt text for helping users create an incident
        """
        return """
        I'll help you create a new ServiceNow incident. Please provide the following information:
        
        1. Short Description: A brief title for the incident (required)
        2. Detailed Description: A thorough explanation of the issue (required)
        3. Caller: The person reporting the issue (optional)
        4. Category and Subcategory: The type of issue (optional)
        5. Impact (1-High, 2-Medium, 3-Low): How broadly this affects users (optional)
        6. Urgency (1-High, 2-Medium, 3-Low): How time-sensitive this issue is (optional)
        
        After collecting this information, I'll use the create_incident tool to submit the incident to ServiceNow.
        """


# Factory functions for creating authentication objects
def create_basic_auth(username: str, password: str) -> BasicAuth:
    """Create BasicAuth object for ServiceNow authentication"""
    return BasicAuth(username, password)

def create_token_auth(token: str) -> TokenAuth:
    """Create TokenAuth object for ServiceNow authentication"""
    return TokenAuth(token)

def create_oauth_auth(client_id: str, client_secret: str, 
                     username: str, password: str,
                     instance_url: str) -> OAuthAuth:
    """Create OAuthAuth object for ServiceNow authentication"""
    return OAuthAuth(client_id, client_secret, username, password, instance_url)
