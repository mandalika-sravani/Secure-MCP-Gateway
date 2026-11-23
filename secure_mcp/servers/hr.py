"""HR MCP server. Row-level scoping happens HERE, from the verified caller token,
never from anything the model says."""
from mcp.server.mcpserver import MCPServer

from ..auth import verify_server_token
from ..data import EMPLOYEES


def _can_view(me, emp_id: str) -> bool:
    emp = EMPLOYEES.get(emp_id)
    if emp is None:
        return False
    if me.role == "admin" or emp_id == me.user_id:
        return True
    return me.role == "manager" and emp["dept"] == me.department


def build() -> MCPServer:
    s = MCPServer("hr")

    @s.tool()
    def get_employee_profile(employee_id: str, caller_token: str) -> dict:
        """Get an employee's name, department, title and work email (no pay data)."""
        me = verify_server_token(caller_token, "hr")
        if not _can_view(me, employee_id):
            raise PermissionError("not found or not permitted")  # same message: no existence leak
        e = EMPLOYEES[employee_id]
        return {"employee_id": employee_id, "name": e["name"], "department": e["dept"],
                "title": e["title"], "email": e["email"]}

    @s.tool()
    def get_salary(employee_id: str, caller_token: str) -> dict:
        """Get an employee's annual salary. Employees can see only their own."""
        me = verify_server_token(caller_token, "hr")
        if not _can_view(me, employee_id):
            raise PermissionError("not found or not permitted")
        return {"employee_id": employee_id, "salary": EMPLOYEES[employee_id]["salary"],
                "currency": "USD", "classification": "restricted"}

    @s.tool()
    def list_team(department: str, caller_token: str) -> list[dict]:
        """List employees in a department. Managers: own department only. Admins: any."""
        me = verify_server_token(caller_token, "hr")
        if me.role == "employee" or (me.role == "manager" and department != me.department):
            raise PermissionError("not found or not permitted")
        return [{"employee_id": k, "name": v["name"], "title": v["title"]}
                for k, v in EMPLOYEES.items() if v["dept"] == department]

    @s.tool()
    def export_all_salaries(caller_token: str) -> list[dict]:
        """Bulk export of all salaries. Admin-only on the server, and deliberately NOT exposed
        by the gateway policy: unlisted tools are denied by default."""
        me = verify_server_token(caller_token, "hr")
        if me.role != "admin":
            raise PermissionError("not permitted")
        return [{"employee_id": k, "salary": v["salary"]} for k, v in EMPLOYEES.items()]

    return s
