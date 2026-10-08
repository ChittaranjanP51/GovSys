# =====================================================================
# GovSys authorization policy.
# One decision endpoint for every governed action:
#   invoke_agent  - may this human use this agent?
#   handoff       - may agent A delegate to agent B for this human?
#   tool_call     - may this agent call this tool, with these args, for this human?
#   read_pii      - may this human see unmasked PII?
# Default deny: allow only when there is no deny reason.
# Query: POST /v1/data/govsys/authz/decision
# =====================================================================
package govsys.authz

import rego.v1

default allow := false

allow if count(deny) == 0

decision := {
	"allow": allow,
	"deny": deny,
	"action": input.action,
}

roles := data.govsys.roles

agents := data.govsys.agents

# ------------------------------------------------------- derived facts
user_agents contains a if {
	some r in input.user.roles
	some a in roles[r].agents
}

user_perms contains p if {
	some r in input.user.roles
	some p in roles[r].permissions
}

known_actions := {"invoke_agent", "handoff", "tool_call", "read_pii"}

# ------------------------------------------------------ common checks
deny contains "unknown action" if not input.action in known_actions

deny contains "missing human identity" if not input.user.sub

deny contains msg if {
	not input.user.status == "active"
	msg := sprintf("user '%v' is not active", [input.user.sub])
}

# Agent workload identity must be registered and match its SPIFFE ID.
agent_actions := {"handoff", "tool_call"}

deny contains msg if {
	input.action in agent_actions
	not agents[input.agent.name]
	msg := sprintf("agent '%v' is not registered", [input.agent.name])
}

deny contains msg if {
	input.action in agent_actions
	agents[input.agent.name].spiffe_id != input.agent.spiffe_id
	msg := sprintf("agent identity mismatch: %v is not %v", [input.agent.spiffe_id, input.agent.name])
}

# Delegation: the agent must be acting on behalf of the requesting human.
deny contains "delegation chain broken: agent is not acting for this user" if {
	input.action in agent_actions
	input.agent.on_behalf_of != input.user.sub
}

# ------------------------------------------------------- invoke_agent
deny contains msg if {
	input.action == "invoke_agent"
	not input.target_agent in user_agents
	msg := sprintf("roles %v may not use the '%v' agent", [input.user.roles, input.target_agent])
}

# ------------------------------------------------------------ handoff
deny contains msg if {
	input.action == "handoff"
	not input.target_agent in data.govsys.handoffs[input.agent.name]
	msg := sprintf("agent '%v' may not hand off to '%v'", [input.agent.name, input.target_agent])
}

deny contains msg if {
	input.action == "handoff"
	not input.target_agent in user_agents
	msg := sprintf("roles %v may not use the '%v' agent", [input.user.roles, input.target_agent])
}

# ---------------------------------------------------------- tool_call
deny contains msg if {
	input.action == "tool_call"
	not input.tool in agents[input.agent.name].tools
	msg := sprintf("agent '%v' has no capability '%v'", [input.agent.name, input.tool])
}

deny contains msg if {
	input.action == "tool_call"
	not input.tool in user_perms
	msg := sprintf("roles %v lack permission '%v'", [input.user.roles, input.tool])
}

deny contains msg if {
	input.action == "tool_call"
	input.tool == "billing.issue_refund"
	input.args.amount > data.govsys.limits.refund_auto_approve
	not "finance_manager" in input.user.roles
	msg := sprintf("refund %v exceeds auto-approve limit %v (needs finance_manager)", [input.args.amount, data.govsys.limits.refund_auto_approve])
}

deny contains "refund amount must be positive" if {
	input.action == "tool_call"
	input.tool == "billing.issue_refund"
	input.args.amount <= 0
}

deny contains msg if {
	input.action == "tool_call"
	input.tool == "order.update_status"
	not input.args.status in data.govsys.limits.agent_settable_status
	msg := sprintf("agents may not set order status to '%v'", [input.args.status])
}

# ----------------------------------------------------------- read_pii
deny contains "user lacks pii.read permission" if {
	input.action == "read_pii"
	not "pii.read" in user_perms
}
