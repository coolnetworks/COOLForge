#!/usr/bin/env node
/**
 * COOLForge MeshCentral Group Provisioner
 *
 * Iterates all Level.io device groups, creates corresponding MeshCentral
 * device groups, and writes the meshid back to each Level.io group via
 * the custom field: policy_meshcentral_meshid (one value per group via assigned_to_id)
 *
 * Run whenever a new Level.io group is created.
 *
 * Usage:
 *   node tools/provision-mesh-groups.js [--dry-run]
 *
 * Config (set via environment or edit defaults below):
 *   LEVEL_API_KEY          - Level.io API key
 *   MESH_URL               - MeshCentral server wss:// URL
 *   MESH_USER              - MeshCentral username
 *   MESH_PASS              - MeshCentral password
 *   MESHID_FIELD           - Level.io custom field name (default: policy_meshcentral_meshid)
 */

'use strict';

const https  = require('https');
const http   = require('http');
const path   = require('path');
const fs     = require('fs');
const { spawnSync } = require('child_process');

// ── Config ────────────────────────────────────────────────────────────────────
const DRY_RUN    = process.argv.includes('--dry-run');
const LEVEL_KEY  = process.env.LEVEL_API_KEY  || 'gTcBnH3fxnPWFp4mX17tFE7D';
const LEVEL_URL  = 'https://api.level.io/v2';
const MESH_URL   = process.env.MESH_URL       || 'wss://mc.cool.net.au';
const MESH_USER  = process.env.MESH_USER      || 'levelcreation';
const MESH_PASS  = process.env.MESH_PASS      || 'r*S2vJIoydUop4F#EKE!wsAL@dOVDpGDpdg9clOLAzWoea!k';
const MESHID_FIELD = process.env.MESHID_FIELD || 'policy_meshcentral_meshid';
const MESHCTRL   = path.join(__dirname, '..', 'vendor', 'meshctrl.js');

// ── Helpers ───────────────────────────────────────────────────────────────────
function log(msg) { console.log(`[${new Date().toISOString().slice(11,19)}] ${msg}`); }
function warn(msg) { console.warn(`[${new Date().toISOString().slice(11,19)}] WARN  ${msg}`); }

/** Sanitise Level group path to MeshCentral group name
 *  "COOLNETWORKS/infra" -> "COOLNETWORKS infra"
 */
function sanitisePath(path) {
    return path
        .replace(/\s*\/\s*/g, ' ')  // slashes -> spaces
        .replace(/^[^A-Za-z]*/, '') // strip leading non-alpha
        .replace(/\s+/g, ' ')       // normalise whitespace
        .trim();
}

/** Simple HTTPS/HTTP request returning parsed JSON */
function apiRequest(url, method, headers, body) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const opts = {
            hostname: parsed.hostname,
            port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path:     parsed.pathname + parsed.search,
            method:   method || 'GET',
            headers:  headers || {}
        };
        const mod = parsed.protocol === 'https:' ? https : http;
        const req = mod.request(opts, res => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
                catch { resolve({ status: res.statusCode, body: data }); }
            });
        });
        req.on('error', reject);
        if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
        req.end();
    });
}

const levelHeaders = {
    'Authorization': LEVEL_KEY,
    'Content-Type':  'application/json',
    'Accept':        'application/json'
};

/** Level.io API call with pagination */
async function levelGet(endpoint) {
    let results = [];
    let url = `${LEVEL_URL}${endpoint}${endpoint.includes('?') ? '&' : '?'}limit=100`;
    while (url) {
        const r = await apiRequest(url, 'GET', levelHeaders);
        if (r.status !== 200) throw new Error(`Level API ${endpoint} failed: ${r.status}`);
        const data = r.body.data || r.body;
        if (Array.isArray(data)) results = results.concat(data);
        else results.push(data);
        url = r.body.has_more && data.length
            ? `${LEVEL_URL}${endpoint}${endpoint.includes('?') ? '&' : '?'}limit=100&starting_after=${data[data.length-1].id}`
            : null;
    }
    return results;
}

async function levelPatch(endpoint, body) {
    const r = await apiRequest(`${LEVEL_URL}${endpoint}`, 'PATCH', levelHeaders, body);
    return r;
}

/** Run meshctrl.js as subprocess, return parsed JSON output.
 *  IMPORTANT: action must come first in args[] so minimist does not
 *  consume it as the value of --json (e.g. ['adddevicegroup', '--name', 'X'])
 */
function meshctrl(args) {
    // Action + action-specific args first, then auth flags, then --json
    // This prevents minimist consuming the action as --json's value
    const authArgs = [
        '--url',       MESH_URL,
        '--loginuser', MESH_USER,
        '--loginpass', MESH_PASS,
        '--json'
    ];
    const result = spawnSync('node', [MESHCTRL, ...args, ...authArgs], { encoding: 'utf8', timeout: 30000 });
    if (result.error) throw result.error;
    const out = (result.stdout || '').trim();
    try { return JSON.parse(out); }
    catch { return out; }
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
    if (DRY_RUN) log('DRY-RUN mode — no changes will be made');

    // 1. Fetch all Level.io groups
    log('Fetching Level.io groups...');
    const levelGroups = await levelGet('/groups');
    log(`Found ${levelGroups.length} Level.io groups`);

    // Build parent lookup for path construction
    const byId = Object.fromEntries(levelGroups.map(g => [g.id, g]));

    function buildPath(g) {
        const parts = [g.name];
        let pid = g.parent_id;
        while (pid && byId[pid]) {
            parts.unshift(byId[pid].name);
            pid = byId[pid].parent_id;
        }
        return parts.join('/');
    }

    // 2. Get Level.io custom field ID for meshid field
    log(`Looking up custom field: ${MESHID_FIELD}`);
    const fields = await levelGet('/custom_fields');
    const meshidField = fields.find(f => f.name === MESHID_FIELD);
    if (!meshidField) {
        console.error(`ERROR: Custom field '${MESHID_FIELD}' not found in Level.io. Run subagent to create it first.`);
        process.exit(1);
    }
    log(`Found field '${MESHID_FIELD}' id=${meshidField.id}`);

    // 3. Fetch existing MeshCentral groups
    log('Fetching MeshCentral device groups...');
    const mcGroups = meshctrl(['listdevicegroups']);
    const mcByName = {};
    if (Array.isArray(mcGroups)) {
        for (const g of mcGroups) {
            mcByName[g.name] = g._id.replace('mesh//', '');
        }
    }
    log(`Found ${Object.keys(mcByName).length} MeshCentral groups`);

    // 4. Iterate Level groups
    const results = { created: [], existing: [], failed: [], skipped: [] };

    for (const group of levelGroups) {
        const levelPath = buildPath(group);
        const mcName    = sanitisePath(levelPath);

        let meshid = mcByName[mcName] || null;
        let action = meshid ? 'existing' : 'create';

        if (!meshid) {
            if (DRY_RUN) {
                log(`  [DRY-RUN] Would create MC group: "${mcName}"`);
                results.skipped.push({ levelPath, mcName });
                continue;
            }

            log(`  Creating MC group: "${mcName}"...`);
            const createResult = meshctrl(['adddevicegroup', '--name', mcName]);
            // Returns "ok mesh//MESHID" or error
            if (typeof createResult === 'string' && createResult.startsWith('ok ')) {
                meshid = createResult.replace('ok mesh//', '').trim();
                mcByName[mcName] = meshid;
                results.created.push({ levelPath, mcName, meshid });
                log(`  Created: meshid=${meshid}`);
            } else {
                warn(`  Failed to create MC group "${mcName}": ${JSON.stringify(createResult)}`);
                results.failed.push({ levelPath, mcName, error: JSON.stringify(createResult) });
                continue;
            }
        } else {
            log(`  Existing MC group: "${mcName}" meshid=${meshid}`);
            results.existing.push({ levelPath, mcName, meshid });
        }

        // 5. Write meshid to Level.io group via per-group custom field value
        if (DRY_RUN) {
            log(`  [DRY-RUN] Would write meshid to Level group "${group.name}" (id=${group.id.slice(-8)})`);
            continue;
        }

        const setResult = await levelPatch('/custom_field_values', {
            custom_field_id: meshidField.id,
            assigned_to_id:  group.id,
            value:           meshid
        });

        if (setResult.status === 200 || setResult.status === 201) {
            log(`  Wrote meshid to Level group "${group.name}" OK`);
        } else {
            warn(`  Failed to write meshid to Level group "${group.name}": HTTP ${setResult.status}`);
        }
    }

    // 7. Summary
    console.log('');
    console.log('============================================================');
    console.log(' SUMMARY');
    console.log('============================================================');
    console.log(`  MC groups created:  ${results.created.length}`);
    console.log(`  MC groups existing: ${results.existing.length}`);
    console.log(`  Failed:             ${results.failed.length}`);
    if (DRY_RUN) console.log(`  Skipped (dry-run):  ${results.skipped.length}`);

    if (results.created.length) {
        console.log('\n  Created:');
        for (const r of results.created) console.log(`    "${r.levelPath}" → "${r.mcName}" (${r.meshid.slice(0,12)}...)`);
    }
    if (results.failed.length) {
        console.log('\n  Failed:');
        for (const r of results.failed) console.log(`    "${r.levelPath}": ${r.error}`);
    }
    console.log('');
}

main().catch(err => { console.error('FATAL:', err); process.exit(1); });
