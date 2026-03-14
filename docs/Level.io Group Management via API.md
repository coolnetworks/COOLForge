# Level.io Custom Fields — API Reference Guide

How to read and write custom field values at every level of the hierarchy via the Level.io v2 REST API.

---

## Authentication

All requests require the API key in the `Authorization` header — raw key, no prefix:

```
Authorization: your-api-key-here
Content-Type: application/json
```

Base URL: `https://api.level.io/v2`

---

## The Hierarchy

```
Organisation (global default)
  └── Group (override)
        └── Child Group (override)
              └── Device (override — highest priority)
```

Values cascade down. A device inherits its group's value unless a device-level override is set.

---

## Custom Field Definitions

Before reading or writing values, you need the field's `name` (not `id`, not the `cf_` reference).

```
GET /v2/custom_fields?limit=100
```

Response fields of interest:

| Property | Example | Notes |
|----------|---------|-------|
| `id` | `Z2lkOi8v...` | GID — needed for some reads |
| `name` | `policy_meshcentral_meshid` | Use this for writes |
| `reference` | `cf_policy_meshcentral_meshid` | Template variable — NOT for API writes |

Paginate with `?limit=100&starting_after=<last_id>` if you have many fields.

---

## Global / Organisation Default

This is the fallback value for all groups and devices that have no override.

### Read
```
GET /v2/custom_field_values?limit=100
```
Returns all fields where no entity override is set (org-level defaults).

### Write
```
PATCH /v2/custom_field_values
{
  "custom_field_id": "Z2lkOi8v...",
  "assigned_to_id": null,
  "value": "your-value"
}
```

---

## Group Level

> ⚠️ **Critical**: `PATCH /v2/custom_field_values` with a group ID as `assigned_to_id` returns HTTP 200 but **silently discards the value**. Always use `PATCH /v2/groups/<id>` instead.

> ⚠️ **Critical**: `GET /v2/custom_field_values?assigned_to_id=<group_id>` returns the **inherited global default**, not any group-level override. Always read via `GET /v2/groups/<id>`.

### Read
```
GET /v2/groups/<group_id>
```
The response includes a `custom_fields` object with all explicit overrides set on that group:
```json
{
  "id": "Z2lkOi8v...",
  "name": "ACME Corp",
  "custom_fields": {
    "policy_meshcentral_meshid": "abc123...",
    "policy_chrome": "install"
  }
}
```
Fields not listed here are inherited from the parent group or org default.

### Write
```
PATCH /v2/groups/<group_id>
{
  "custom_fields": {
    "policy_meshcentral_meshid": "abc123..."
  }
}
```

Use the field **`name`** as the key — not the `cf_` reference and not the field ID.

### List Groups
```
GET /v2/groups?limit=100
```
Paginate with `starting_after`. Groups are what Level.io calls clients/organisations — there is no `/v2/folders` or `/v2/organizations` endpoint (both return 404).

---

## Device Level

### Read (effective value — includes inheritance)
```
GET /v2/custom_field_values?assigned_to_id=<device_id>&limit=100
```
Returns the effective value for that device — either the device override or the inherited value from its group chain. This endpoint works correctly for devices (unlike groups).

### Write (device-level override)
```
PATCH /v2/custom_field_values
{
  "custom_field_id": "Z2lkOi8v...",
  "assigned_to_id": "<device_id>",
  "value": "your-value"
}
```

Use the field `id` (GID) here, not the name.

### List Devices
```
GET /v2/devices?limit=100
```
Key device properties: `id`, `hostname`, `group_id`, `group_name`, `platform` (e.g. "Windows", "Linux").

---

## Detecting Explicit Group Overrides vs Inherited Values

There is no bulk endpoint for this. You must query each group individually:

```
GET /v2/groups/<group_id>
```

Check whether the field appears in `.custom_fields`. If it does, that group has an explicit override. If not, it's inheriting from a parent or the org default.

At scale (many groups × many fields) this requires individual per-group queries. Rate limit is **100 calls/min** — allow 600ms between calls.

---

## Quick Reference

| Goal | Endpoint | Method | Notes |
|------|----------|--------|-------|
| Read org default | `/v2/custom_field_values` | GET | Filter by `custom_field_id` client-side |
| Write org default | `/v2/custom_field_values` | PATCH | `assigned_to_id: null` |
| Read group override | `/v2/groups/<id>` | GET | Check `.custom_fields` |
| Write group override | `/v2/groups/<id>` | PATCH | Body: `{"custom_fields": {"name": "value"}}` |
| Read device effective value | `/v2/custom_field_values?assigned_to_id=<device_id>` | GET | Returns inherited or override |
| Write device override | `/v2/custom_field_values` | PATCH | Use field GID + device `assigned_to_id` |
| List groups | `/v2/groups` | GET | Paginate with `limit` + `starting_after` |
| List devices | `/v2/devices` | GET | Paginate with `limit` + `starting_after` |
| List field definitions | `/v2/custom_fields` | GET | Get field `name` and `id` |

---

## Common Mistakes

| Mistake | Result | Fix |
|---------|--------|-----|
| `PATCH /v2/custom_field_values` with group `assigned_to_id` | HTTP 200 but value not saved | Use `PATCH /v2/groups/<id>` |
| `GET /v2/custom_field_values?assigned_to_id=<group_id>` | Returns global default, not group override | Use `GET /v2/groups/<id>` |
| Using `cf_field_name` as key in group PATCH body | Field not found / silently ignored | Use `field_name` (no `cf_` prefix) |
| Using field `id` (GID) as key in group PATCH body | Field not found | Use field `name` |
| Calling `/v2/folders` or `/v2/organizations` | 404 | Use `/v2/groups` |
| Adding `Bearer` to Authorization header | 401 | Raw key only, no prefix |
