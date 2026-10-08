package govsys.authz_test

import rego.v1

import data.govsys.authz

alice := {"sub": "alice", "roles": ["support"], "status": "active"}

bob := {"sub": "bob", "roles": ["finance"], "status": "active"}

fiona := {"sub": "fiona", "roles": ["finance", "finance_manager"], "status": "active"}

ian := {"sub": "ian", "roles": ["intern"], "status": "active"}

mallory := {"sub": "mallory", "roles": ["support"], "status": "suspended"}

agent(name, user) := {
	"name": name,
	"spiffe_id": sprintf("spiffe://govsys.local/agent/%v", [name]),
	"on_behalf_of": user.sub,
}

test_support_can_invoke_order if {
	authz.allow with input as {"action": "invoke_agent", "user": alice, "target_agent": "order"}
}

test_intern_cannot_invoke_billing if {
	not authz.allow with input as {"action": "invoke_agent", "user": ian, "target_agent": "billing"}
}

test_suspended_user_denied if {
	not authz.allow with input as {"action": "invoke_agent", "user": mallory, "target_agent": "order"}
}

test_order_can_handoff_to_billing if {
	authz.allow with input as {"action": "handoff", "user": alice, "agent": agent("order", alice), "target_agent": "billing"}
}

test_billing_cannot_handoff_to_admin if {
	not authz.allow with input as {"action": "handoff", "user": fiona, "agent": agent("billing", fiona), "target_agent": "admin"}
}

test_spoofed_agent_identity_denied if {
	not authz.allow with input as {
		"action": "tool_call", "user": alice, "tool": "order.lookup", "args": {"order_id": 1001},
		"agent": {"name": "order", "spiffe_id": "spiffe://evil.example/agent/order", "on_behalf_of": "alice"},
	}
}

test_broken_delegation_denied if {
	not authz.allow with input as {
		"action": "tool_call", "user": alice, "tool": "order.lookup", "args": {"order_id": 1001},
		"agent": agent("order", bob),
	}
}

test_agent_cannot_call_other_agents_tool if {
	not authz.allow with input as {"action": "tool_call", "user": carol_admin, "tool": "billing.issue_refund", "args": {"amount": 10}, "agent": agent("order", carol_admin)}
}

carol_admin := {"sub": "carol", "roles": ["admin"], "status": "active"}

test_support_cannot_refund if {
	not authz.allow with input as {"action": "tool_call", "user": alice, "tool": "billing.issue_refund", "args": {"amount": 50}, "agent": agent("billing", alice)}
}

test_finance_small_refund_allowed if {
	authz.allow with input as {"action": "tool_call", "user": bob, "tool": "billing.issue_refund", "args": {"amount": 50}, "agent": agent("billing", bob)}
}

test_finance_large_refund_denied if {
	not authz.allow with input as {"action": "tool_call", "user": bob, "tool": "billing.issue_refund", "args": {"amount": 549}, "agent": agent("billing", bob)}
}

test_finance_manager_large_refund_allowed if {
	authz.allow with input as {"action": "tool_call", "user": fiona, "tool": "billing.issue_refund", "args": {"amount": 549}, "agent": agent("billing", fiona)}
}

test_status_whitelist if {
	not authz.allow with input as {"action": "tool_call", "user": alice, "tool": "order.update_status", "args": {"order_id": 1004, "status": "delivered"}, "agent": agent("order", alice)}
}

test_pii_read if {
	authz.allow with input as {"action": "read_pii", "user": alice}
	not authz.allow with input as {"action": "read_pii", "user": bob}
}
