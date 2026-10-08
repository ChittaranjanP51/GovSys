"""Business tools. Each tool belongs to exactly one agent and executes under that
agent's own least-privilege Postgres role (see infra/postgres/02_roles.sql)."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Callable

from governance.data_governance import agent_connection


class ToolError(Exception):
    pass


@dataclass
class Tool:
    name: str
    agent: str
    description: str
    fn: Callable
    source: dict          # result key -> (schema, table, column) for catalog classification


def _rows(cur) -> list[dict]:
    return [{k: (float(v) if isinstance(v, Decimal) else v) for k, v in r.items()} for r in cur.fetchall()]


# ------------------------------------------------------------------ order agent
def order_lookup(conn, order_id: int, **_):
    rows = _rows(conn.execute(
        """SELECT o.order_id, o.item, o.quantity, o.total, o.status, o.created_at::date AS ordered_on,
                  c.customer_id, c.full_name, c.email, c.phone
           FROM sales.orders o JOIN sales.customers c USING (customer_id) WHERE o.order_id = %s""", (order_id,)))
    if not rows:
        raise ToolError(f"order {order_id} not found")
    return rows


def order_customer_orders(conn, customer_id: int, **_):
    return _rows(conn.execute(
        """SELECT o.order_id, o.item, o.total, o.status, c.full_name FROM sales.orders o
           JOIN sales.customers c USING (customer_id) WHERE c.customer_id = %s ORDER BY o.order_id""", (customer_id,)))


def order_update_status(conn, order_id: int, status: str, **_):
    rows = _rows(conn.execute(
        "UPDATE sales.orders SET status = %s, updated_at = now() WHERE order_id = %s RETURNING order_id, status",
        (status, order_id)))
    if not rows:
        raise ToolError(f"order {order_id} not found")
    return rows


# ---------------------------------------------------------------- billing agent
def billing_get_invoice(conn, order_id: int, **_):
    rows = _rows(conn.execute(
        "SELECT invoice_id, order_id, amount, status, card_last4 FROM billing.invoices WHERE order_id = %s", (order_id,)))
    if not rows:
        raise ToolError(f"no invoice for order {order_id}")
    return rows


def billing_issue_refund(conn, order_id: int, amount: float, reason: str = "", requested_by: str = "",
                         agent_spiffe_id: str = "", **_):
    inv = conn.execute("SELECT invoice_id, amount, status FROM billing.invoices WHERE order_id = %s", (order_id,)).fetchone()
    if not inv:
        raise ToolError(f"no invoice for order {order_id}")
    if inv["status"] not in ("paid", "partially_refunded"):
        raise ToolError(f"invoice {inv['invoice_id']} is '{inv['status']}', cannot refund")
    already = conn.execute("SELECT COALESCE(SUM(amount),0) AS s FROM billing.refunds WHERE order_id = %s",
                           (order_id,)).fetchone()["s"]
    remaining = float(inv["amount"]) - float(already)
    if amount > remaining + 1e-9:
        raise ToolError(f"refund {amount:.2f} exceeds refundable balance {remaining:.2f}")
    row = conn.execute(
        """INSERT INTO billing.refunds (order_id, amount, reason, requested_by, executed_by_agent)
           VALUES (%s, %s, %s, %s, %s) RETURNING refund_id, order_id, amount, created_at""",
        (order_id, amount, reason, requested_by, agent_spiffe_id)).fetchone()
    new_status = "refunded" if abs(remaining - amount) < 1e-9 else "partially_refunded"
    conn.execute("UPDATE billing.invoices SET status = %s WHERE order_id = %s", (new_status, order_id))
    return [{**{k: (float(v) if isinstance(v, Decimal) else v) for k, v in row.items()}, "invoice_status": new_status}]


def billing_refund_history(conn, order_id: int | None = None, **_):
    if order_id:
        return _rows(conn.execute("SELECT refund_id, order_id, amount, reason, requested_by, created_at FROM billing.refunds WHERE order_id = %s ORDER BY refund_id", (order_id,)))
    return _rows(conn.execute("SELECT refund_id, order_id, amount, reason, requested_by, created_at FROM billing.refunds ORDER BY refund_id DESC LIMIT 10"))


# ------------------------------------------------------------------ admin agent
def admin_list_staff(conn, **_):
    return _rows(conn.execute("SELECT username, full_name, department, roles, status FROM iam.staff ORDER BY username"))


def admin_audit_summary(conn, **_):
    return _rows(conn.execute(
        """SELECT final_decision, COALESCE(blocked_at, '-') AS blocked_at, count(*) AS requests
           FROM gov.audit_log WHERE ts > now() - interval '7 days'
           GROUP BY 1, 2 ORDER BY 3 DESC"""))


C = ("sales", "customers")
TOOLS: dict[str, Tool] = {t.name: t for t in [
    Tool("order.lookup", "order", "Look up an order by id", order_lookup,
         {"full_name": (*C, "full_name"), "email": (*C, "email"), "phone": (*C, "phone"),
          "total": ("sales", "orders", "total"), "order_id": ("sales", "orders", "order_id"),
          "customer_id": (*C, "customer_id")}),
    Tool("order.customer_orders", "order", "List a customer's orders", order_customer_orders,
         {"full_name": (*C, "full_name"), "total": ("sales", "orders", "total")}),
    Tool("order.update_status", "order", "Cancel / mark returned", order_update_status, {}),
    Tool("billing.get_invoice", "billing", "Get the invoice for an order", billing_get_invoice,
         {"card_last4": ("billing", "invoices", "card_last4"), "amount": ("billing", "invoices", "amount")}),
    Tool("billing.issue_refund", "billing", "Refund an order", billing_issue_refund, {}),
    Tool("billing.refund_history", "billing", "Refund history", billing_refund_history, {}),
    Tool("admin.list_staff", "admin", "List staff accounts and roles", admin_list_staff,
         {"roles": ("iam", "staff", "roles")}),
    Tool("admin.audit_summary", "admin", "Summarize governance decisions", admin_audit_summary, {}),
]}


def execute(tool_name: str, args: dict) -> list[dict]:
    tool = TOOLS[tool_name]
    with agent_connection(tool.agent) as conn:
        with conn.transaction():
            return tool.fn(conn, **args)
