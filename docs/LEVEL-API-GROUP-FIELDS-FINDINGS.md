# Level.io Group-Level Custom Fields — Key Findings

**Date discovered**: 2026-03-14  
**Context**: Building group-aware MeshCentral installer deployment via Level.io custom fields

---

## TL;DR — The Gotchas

### 1. `PATCH /v2/custom_field_values` silently drops group-level values

```
PATCH /v2/custom_field_values
{ "assigned_to_id": "<group_id>", "custom_field_id": "...", "value": "abc" }
→ HTTP 200 ✅ (lies)
→ Value not saved ❌
```

**Always use `PATCH /v2/groups/<group_id>` instead:**
```json
PATCH /v2/groups/Z2lkOi8v...
{ "custom_fields": { "policy_meshcentral_meshid": "abc123..." } }
```
Use field **name** (e.g. `policy_meshcentral_meshid`), not the reference (`cf_policy_meshcentral_meshid`).

---

### 2. Reading group-level overrides is broken via `custom_field_values`

```
GET /v2/custom_field_values?assigned_to_id=<group_id>
→ Returns the inherited GLOBAL default, not the group override
```

**Read overrides via the group object directly:**
```
GET /v2/groups/<group_id>
→ .custom_fields.policy_meshcentral_meshid  ← actual override value
```

---

### 3. Entity type is `"group"` not `"folder"` or `"organization"`

- `/v2/folders` → 404
- `/v2/organizations` → 404
- `/v2/groups` → ✅ this is what Level.io calls clients/orgs/folders

---

### 4. Rate limit: 100 calls/min (600ms between calls)

At 139 groups × 41 fields = 5,699 API calls → ~57 min for a full backup.  
Run long operations detached with `nohup`.

---

### 5. Cascade works correctly

`Org global → Group override → Child group override → Device override`  
Level v2 OpenAPI spec confirms this. Group PATCH correctly cascades to devices.

---

### 6. Auth: no Bearer prefix

```
Authorization: GNRdZpcVjyvZbJ6cvVLgU4zf
```
Raw key only — no `Bearer`, no `Token`.

---

### 7. Primary vs Secondary instances — different field IDs for same field names

Primary: `GNRdZpcVjyvZbJ6cvVLgU4zf` → 139 groups, field ID 7828 for `policy_meshcentral_meshid`  
Secondary (test): `gTcBnH3fxnPWFp4mX17tFE7D` → 6 groups, field ID 7827 for same field  
**Never mix keys between instances.**

---

## Quick Reference

| Goal | Correct method |
|------|---------------|
| Set group field override | `PATCH /v2/groups/<id>` with `custom_fields` body |
| Read group field override | `GET /v2/groups/<id>` → `.custom_fields` |
| Set device field override | `PATCH /v2/custom_field_values` with device `assigned_to_id` ✅ |
| Set global/org default | `PATCH /v2/custom_field_values` with `assigned_to_id=null` ✅ |
| List groups | `GET /v2/groups` (paginated, limit=100) |
