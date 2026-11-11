# Graphical orchestration and security editor

Open **Orchestration** and use **Graphical orchestration & security**.

## Rules

Choose **New connection**, select a consumer and a registered service, set priority, and save. Consumers can also be dragged onto services. Select a connection or **Edit graph** in the stored-rule table to edit it. Change priority or endpoints, save, and use **Delete rule** to remove the selected connection. Filters keep large catalogs manageable; the graph scrolls within its panel on phones. Existing Arrowhead category colors are preserved.

## Security policies

Select **Security policies**, then a service or an existing policy. **New policy** also supports event-type targets. Choose all consumers, an allowlist, or an exclusion list; click consumer nodes or tick membership boxes. Add operation scopes to configure individual operations. Save and delete are explicit actions. **Reload** discards the selected draft and adopts current cloud data.

Only LOCAL management policies are writable. Provider-owned policies are visible as read-only context. A rule does not grant access; authorization policies remain independent. The diagram describes stored configuration, not observed traffic or a complete evaluation of all authorization layers.

## Authority and recovery

Changes use the cloud's existing authenticated orchestration and authorization APIs. Certificate, CRL, host/origin, session and confirmation checks remain enforced. The manager advertises its actual provisioned certificate public key and HTTPS consumer interface. Security-policy delegation is restricted to query/grant/revoke operations. The Go test cloud retains its existing rule create/query/remove permissions and uses replacement for priority changes; Java, chiplet and Rust use their native priority operation.

Edits compare the original record with a fresh authority query and reject stale snapshots. These checks are best effort, not an atomic cross-client transaction. Endpoint replacement stages the new route and confirms it before retiring the old route; recovery attempts restore the prior binding and report incomplete recovery. Java policy replacement requires revoke/grant because the authority rejects duplicate targets, with restoration attempted on failure. Legacy Rust replacement retires the former policy ID after confirming the new row. There may be a brief transition; concurrent external writers cannot be fully serialized by this UI. Query views currently retrieve up to 1,000 policies.

No credentials are embedded in the UI or verification evidence. Existing console passwords and URLs continue to apply.
