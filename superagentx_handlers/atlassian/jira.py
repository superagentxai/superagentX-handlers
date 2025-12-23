import logging
import os
from typing import Any, Optional

from jira import JIRA, Project
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

from superagentx_handlers.atlassian.exceptions import SprintException, AuthException, ProjectException, TaskException

logger = logging.getLogger(__name__)


class JiraHandler(BaseHandler):
    """
        JiraHandler — Async Jira Operations Handler

        This handler centralizes authenticated, asynchronous interactions with
        Atlassian Jira Cloud. It initializes a Jira API client using email + API
        token authentication and exposes a collection of LLM-friendly tool methods
        that perform project discovery, sprint management, issue workflows, ticket
        retrieval, and GRC-focused analysis.

            - get_list_projects            : List all Jira projects
            - get_active_sprint            : Retrieve the active (or filtered) sprint for a board
            - create_sprint                : Create a new sprint with optional dates and description
            - add_issue_to_sprint          : Add an issue into the active sprint
            - move_to_backlog              : Move an issue back to the backlog
            - get_issue                    : Retrieve full details of an issue
            - add_comment_for_issue        : Add a comment to an issue
            - active_sprint_get_all_issues : Fetch all issues from the active sprint
            - active_sprint_issues_by_assignee : Fetch sprint issues assigned to a specific user
            - active_sprint_filter_issues_by_status : Fetch sprint issues filtered by status (To Do, In Progress, etc.)
            - list_all_tickets             : List all Jira tickets with full metadata
            - get_workflow_details         : Retrieve workflow transitions for recent issues
            - get_all_tickets              : Retrieve enriched ticket data useful for auditing, traceability, access control, and
                                             change management evidence. Includes:(descriptions,linked issues,attachmentscomments (normalized text),
                                             worklogs,time tracking details)
    """

    def __init__(
            self,
            *,
            email: str | None = None,
            token: str | None = None,
            organization: str | None = None,
    ):
        super().__init__()
        self.email = email or os.getenv('ATLASSIAN_EMAIL')
        self.token = token or os.getenv('ATLASSIAN_TOKEN')
        self.organization = organization or os.getenv('ATLASSIAN_ORGANIZATION')
        self._connection: JIRA = self._connect()

    def _connect(self) -> JIRA:
        try:
            jira = JIRA(
                server=f'https://{self.organization}.atlassian.net',
                basic_auth=(self.email, self.token)
            )
            logger.info("Authenticate Success")
            return jira
        except Exception as ex:
            message = f'JIRA Handler Authentication Problem {ex}'
            logger.error(message, exc_info=ex)
            raise AuthException(message)

    @tool
    async def get_list_projects(
            self
    ):
        """
        Retrieves a list of projects.
        Discover project names, keys, IDs
        Useful before querying issues, sprints, boards, or workflows

        Returns:
            List[dict]: A list of dictionaries, where each dictionary represents
            a JIRA project with keys such as 'key', 'name', and 'id'.
        """
        try:
            project_list: Project = await sync_to_async(self._connection.projects)
            projects = []
            async for project in iter_to_aiter(project_list):
                temp_data = await sync_to_async(
                    self._connection.project,
                    id=project.id
                )
                projects.append(temp_data.raw)
            return projects
        except Exception as ex:
            message = f"Projects Getting Error! {ex}"
            logger.error(message)
            raise ProjectException(message)

    @tool
    async def get_active_sprint(
            self,
            *,
            board_id: int,
            start: int = 0,
            end: int = 1,
            state: str = 'active'
    ):
        """
        Retrieves the active sprint for a specified board, allowing optional pagination and
        state filtering. This returns details of the active sprint based on the provided board ID and parameters.

            - board_id:	int	ID of the Jira board
            - start	int:	Starting index for pagination
            - end	int:	Number of sprints to return
            - state	str:	Filter by sprint state (active, closed, future)
        """

        try:
            return await sync_to_async(
                self._connection.sprints,
                board_id=board_id,
                startAt=start,
                maxResults=end,
                state=state
            )
        except Exception as ex:
            message = f"Active Sprint Not Found! {ex}"
            logger.error(message)
            raise SprintException(message)

    @tool
    async def create_sprint(
            self,
            *,
            name: str,
            board_id: int,
            start_date: Optional[Any] = None,
            end_date: Optional[Any] = None,
            description: Optional[str] = None
    ):
        """
            Creates a new sprint for the specified board, allowing optional start and end dates
            along with a description.

                - name	str:	Name of the new sprint
                - board_id:	int	Board to attach the sprint to
                - start_date:	Any or None	Optional sprint start date
                - end_date:	Any or None	Optional sprint end date
                - description:	str or None	Sprint goal/summary

        """

        try:
            return await sync_to_async(
                self._connection.create_sprint,
                name=name,
                board_id=board_id,
                startDate=start_date,
                endDate=end_date,
                goal=description
            )
        except Exception as ex:
            message = f"Sprint Creation Failed! {ex}"
            logger.error(message)
            raise SprintException(message)

    @tool
    async def get_issue(
            self,
            *,
            issue_id: str
    ):
        """
        Retrieves the details of a specific issue based on the provided issue ID.
        This method allows users to access issue information for further processing or display.

        parameter:
             issue_id (str): The unique identifier of the issue to be retrieved or processed.
        """
        try:
            res = await sync_to_async(self._connection.issue, id=issue_id)
            return res.raw
        except Exception as ex:
            message = f"Issue Not Found! {ex}"
            logger.error(message)
            raise SprintException(message)

    @tool
    async def add_issue_to_sprint(
            self,
            *,
            board_id: int,
            issue_key: str
    ):
        """
        Add a new issue to the active sprint.

        Parameters:
            board_id (int): The unique identifier of the board associated with the operation.
            issue_key (str): The unique identifier of the issue to be added to the active sprint.
        """

        try:
            current_sprint = await self.get_active_sprint(
                board_id=board_id
            )
            async for sprint in current_sprint:
                return await sync_to_async(
                    self._connection.add_issues_to_sprint,
                    sprint_id=sprint.id,
                    issue_keys=[issue_key]
                )
        except Exception as ex:
            message = f"Failed to add issue! {ex}"
            logger.error(message)
            raise TaskException(message)

    @tool
    async def move_to_backlog(
            self,
            *,
            issue_key: str
    ):
        """
        Moves specified issues to the backlog for better future management.

        parameter:
            issue_key (str): The unique identifier of the issue to which the comment will be added.

        """
        try:
            return await sync_to_async(
                self._connection.move_to_backlog,
                issue_keys=[issue_key]
            )
        except Exception as ex:
            message = f"Failed to move backlog! {ex}"
            logger.error(message)
            raise TaskException(message)

    @tool
    async def add_comment_for_issue(
            self,
            *,
            issue_key: str,
            comments: str
    ):
        """
        Adds a comment to the specified issue identified by the issue key.
        This method enhances collaboration by allowing users to provide feedback or updates directly on the issue.

            parameter:
                issue_key (str): The unique identifier of the issue to which the comment will be added.
                comments (str): The content of the comment to be added to the specified issue.

        """
        try:
            return await sync_to_async(
                self._connection.add_comment,
                issue=issue_key,
                body=comments
            )
        except Exception as ex:
            message = f"Comments added failed! {ex}"
            logger.error(message)
            raise TaskException(message)

    @tool
    async def active_sprint_get_all_issues(
            self,
            *,
            board_id: int,
            start: int = 0,
            end: int = 10
    ):
        """
    Retrieve all issues from the active sprint of a specified board.

    This asynchronous method fetches issues associated with the active sprint
    on the board identified by the given board ID, allowing for pagination
    through the start and end parameters.

    Args:
        board_id (int): The ID of the board for which to retrieve issues.
        start (int, optional): The index of the first issue to return.
                               Defaults to 0.
        end (int, optional): The index of the last issue to return (exclusive).
                             Defaults to 10.

    Returns:
        List[Issue]: A list of issues from the active sprint on the specified board.
    """
        try:
            current_sprint = await self.get_active_sprint(
                board_id=board_id
            )
            if not current_sprint:
                message = f"Active Sprint Not Found!"
                logger.error(message)
                raise SprintException(message)
            sprint_id = current_sprint[0].id
            issues_list = await sync_to_async(
                self._connection.search_issues,
                startAt=start,
                maxResults=end,
                jql_str=f"sprint={sprint_id}"
            )
            issues = []
            async for issue in iter_to_aiter(issues_list):
                issues.append(await self.get_issue(
                    issue_id=issue.id
                ))
            return issues
        except Exception as ex:
            message = f"Search Error! {ex}"
            logger.error(message)
            raise SprintException(message)

    @tool
    async def active_sprint_issues_by_assignee(
            self,
            *,
            assignee_name: str,
            board_id: int,
            start: int = 0,
            end: int = 10
    ):
        """
            Retrieve issues from the active sprint assigned to a specific user.

            This asynchronous method fetches issues from the active sprint on the
            specified board that are assigned to the user identified by
            `assignee_name`. It supports pagination through the `start` and `end`
            parameters.

            Args:
                assignee_name (str): The name of the user to filter issues by.
                board_id (int): The ID of the board from which to retrieve issues.
                start (int, optional): The index of the first issue to return.
                                       Defaults to 0.
                end (int, optional): The index of the last issue to return (exclusive).
                                     Defaults to 10.

            Returns:
                List[Issue]: A list of issues from the active sprint assigned to the
                              specified user on the given board.
            """
        try:
            current_sprint = await self.get_active_sprint(
                board_id=board_id
            )
            if not current_sprint:
                message = f"Active Sprint Not Found!"
                logger.error(message)
                raise SprintException(message)
            sprint_id = current_sprint[0].id
            issues_list = await sync_to_async(
                self._connection.search_issues,
                startAt=start,
                maxResults=end,
                jql_str=f'assignee="{assignee_name}" AND sprint={sprint_id}'
            )
            issues = []
            async for issue in iter_to_aiter(issues_list):
                issues.append(await self.get_issue(
                    issue_id=issue.id
                ))
            return issues
        except Exception as ex:
            message = f"Search Error! {ex}"
            logger.error(message)
            raise SprintException(message)

    @tool
    async def active_sprint_filter_issues_by_status(
            self,
            *,
            filter_by: str,
            board_id: int,
            start: int = 0,
            end: int = 10
    ):
        """
            Retrieve issues from the active sprint filtered by specific statuses such as
             'In Progress', 'To Do', 'Done', etc..

            This asynchronous method fetches issues from the active sprint on the
            specified board that match the given `filter_status`. It supports pagination
            through the `start` and `end` parameters.

            Args:
                filter_by (str): The status to filter issues statuses
                board_id (int): The ID of the board from which to retrieve issues.
                start (int, optional): The index of the first issue to return.
                                       Defaults to 0.
                end (int, optional): The index of the last issue to return (exclusive).
                                     Defaults to 10.

            Returns:
                List[Issue]: A list of issues from the active sprint that match the
                              specified status on the given board.
            """
        try:
            current_sprint = await self.get_active_sprint(
                board_id=board_id
            )
            if not current_sprint:
                message = f"Active Sprint Not Found!"
                logger.error(message)
                raise SprintException(message)
            sprint_id = current_sprint[0].id
            issues_list = await sync_to_async(
                self._connection.search_issues,
                startAt=start,
                maxResults=end,
                jql_str=f'status="{filter_by}" AND sprint={sprint_id}'
            )
            issues = []
            async for issue in iter_to_aiter(issues_list):
                issues.append(await self.get_issue(
                    issue_id=issue.id
                ))
            return issues
        except Exception as ex:
            message = f"Search Error! {ex}"
            logger.error(message)
            raise SprintException(message)

    @tool
    async def list_all_tickets(
            self,
            start: int = 0,
            end: int = 50
    ):
        """
        List all Jira tickets with full properties.

        This method retrieves all tickets across projects, paginated, and returns full issue details.

        Args:
            start (int, optional): The index of the first ticket to return. Defaults to 0.
            end (int, optional): The index of the last ticket to return (exclusive). Defaults to 50.

        Returns:
            List[dict]: A list of issue dictionaries with all properties.
        """
        try:
            issues_list = await sync_to_async(
                self._connection.search_issues,
                jql_str='ORDER BY created DESC',
                startAt=start,
                maxResults=end
            )
            issues = []
            async for issue in iter_to_aiter(issues_list):
                issue_data = await self.get_issue(issue_id=issue.id)
                issues.append(issue_data)
            # logger.info(issues_list)
            return issues
        except Exception as ex:
            message = f"Failed to fetch all tickets! {ex}"
            logger.error(message)
            raise TaskException(message)

    @tool
    async def get_workflow_details(
            self,
            start: int = 0,
            end: int = 50
    ):
        """
        Retrieves workflow details for a Jira issue associated with control objectives
        such as 'Access Control' or 'Change Management'.

        This method is used in GRC contexts to track the workflow status and transitions
        of Jira tickets that are linked to specific control objectives. It helps ensure
        traceability, accountability, and proper change governance by showing current
        issue state and possible next steps in the workflow.

        Args:
            start (int, optional): The index of the first ticket to return. Defaults to 0.
            end (int, optional): The index of the last ticket to return (exclusive). Defaults to 50.
        :return: Dict with workflow info
        """
        logger.info("Workflow")
        issues_list = await sync_to_async(
            self._connection.search_issues,
            jql_str='ORDER BY created DESC',
            startAt=start,
            maxResults=end
        )
        datas = []
        async for issue in iter_to_aiter(issues_list):
            issue = await sync_to_async(self._connection.issue, id=issue.id)
            transitions = await sync_to_async(self._connection.transitions, issue)
            datas.append(transitions)
        return datas

    @tool
    async def get_all_tickets(
            self,
            start: int = 0,
            end: int = 50
    ):
        """
        Retrieve Jira tickets relevant to GRC analysis, including full metadata and relationships.

        This method fetches Jira tickets across projects (paginated by `start` and `end`)
        and extracts fields useful for Governance, Risk, and Compliance (GRC) activities.
        The returned ticket data includes control-relevant information such as descriptions,
        project details, linked issues, attachments, comments, worklogs, and time tracking.

        Example GRC use cases:
        - Audit evidence for control objectives (e.g., Access Control, Change Management)
        - Traceability of tasks, approvals, and documentation
        - Workflow or accountability analysis

        Args:
            start (int, optional): The index of the first ticket to return. Defaults to 0.
            end (int, optional): The index of the last ticket to return (exclusive). Defaults to 50.

        Returns:
            List[dict]: A list of issue dictionaries with fields extracted for GRC purposes.
        """
        logger.info(f"Fetching......")

        try:
            issues_list = await sync_to_async(
                self._connection.search_issues,
                jql_str='ORDER BY created DESC',
                startAt=start,
                maxResults=end
            )
            issues = []
            async for issue in iter_to_aiter(issues_list):
                issue_data = await self.get_issue(issue_id=issue.id)
                fields = issue_data.get("fields", {})

                result = {
                    "issue_key": issue_data.get("key"),
                    "issue_id": issue_data.get("id"),
                    "summary": fields.get("summary"),
                    "description": await self.extract_description(fields.get("description")),
                    "project_key": fields.get("project", {}).get("key"),
                    "project_name": fields.get("project", {}).get("name"),
                    "issue_links": [link.get("outwardIssue", {}).get("key") or link.get("inwardIssue", {}).get("key")
                                    for link in fields.get("issuelinks", [])],
                    "attachments": [att.get("filename") for att in fields.get("attachment", [])],
                    "comments": [await self.extract_comment_text(c.get("body")) for c in
                                 fields.get("comment", {}).get("comments", [])],
                    "worklogs": [{
                        "author": wl.get("author", {}).get("displayName"),
                        "comment": await self.extract_comment_text(wl.get("comment")),
                        "timeSpent": wl.get("timeSpent")
                    } for wl in fields.get("worklog", {}).get("worklogs", [])],
                    "time_tracking": {
                        "original_estimate": fields.get("timetracking", {}).get("originalEstimate"),
                        "remaining_estimate": fields.get("timetracking", {}).get("remainingEstimate"),
                        "time_spent": fields.get("timetracking", {}).get("timeSpent")
                    }
                }
                issues.append(result)
            return issues
        except Exception as ex:
            message = f"Failed to fetch all tickets! {ex}"
            logger.error(message)
            return []

    @staticmethod
    async def extract_description(desc):
        if not desc: return ""
        try:
            return " ".join([
                item["text"] for para in desc.get("content", [])
                for item in para.get("content", []) if item.get("type") == "text"
            ])
        except Exception as ex:
            return ""

    @staticmethod
    async def extract_comment_text(comment):
        if not comment: return ""
        try:
            return " ".join([
                item["text"] for para in comment.get("content", [])
                for item in para.get("content", []) if item.get("type") == "text"
            ])
        except Exception as ex:
            return ""
