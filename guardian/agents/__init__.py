"""Optional bounded LLM roles (Analyst, Remediator, Critic) and the per-finding
remediation workflow.  Owner: Role C.

None of these modules executes commands, approves proposals or changes scanner
facts.  Every model call goes through ``guardian.llm.call`` and every model
statement through ``guardian.claims`` / ``guardian.guard``.
"""
