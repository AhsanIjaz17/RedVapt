/**
 * verifyImprovements.js — Unit tests for scanner improvements
 */
import { discoverParameters } from '../src/utils/paramDiscovery.js';
import { classifyResponse, getAdaptivePayload } from '../src/engine/vuln/adaptivePayloads.js';

async function testParamDiscovery() {
    console.log('--- Testing Parameter Discovery ---');
    const endpoints = [
        'https://example.com/api/v1/user?id=123',
        'https://example.com/search?q=test&page=1',
        'https://example.com/static/style.css'
    ];
    const forms = [
        { action: 'https://example.com/login', method: 'POST', inputs: [{ name: 'user' }, { name: 'pass' }] }
    ];

    const results = discoverParameters(endpoints, forms);
    console.log('Discovered Params:', results);

    const loginRow = results.find(r => r.url.includes('login'));
    if (loginRow && loginRow.params.includes('user') && loginRow.params.includes('pass')) {
        console.log('✅ Form param discovery passed');
    } else {
        console.log('❌ Form param discovery failed');
    }

    const apiRow = results.find(r => r.url.includes('api/v1/user'));
    if (apiRow && apiRow.params.includes('id')) {
        console.log('✅ URL param discovery passed');
    } else {
        console.log('❌ URL param discovery failed');
    }
}

async function testAdaptivePayloads() {
    console.log('\n--- Testing Adaptive Payloads ---');

    // Test SQL Error Detection
    const mysqlError = 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version';
    const hints = classifyResponse(mysqlError, 500);
    console.log('Hints for MySQL error:', hints);
    if (hints.includes('MYSQL_DRIVEN')) {
        console.log('✅ MySQL error classification passed');
    } else {
        console.log('❌ MySQL error classification failed');
    }

    // Test Adaptive Payload Generation
    const payload = getAdaptivePayload('SQLi', ['MYSQL_DRIVEN'], 'rvtok_123');
    console.log('Adaptive SQLi Payload:', payload);
    if (payload && !payload.toLowerCase().includes('waitfor delay')) {
        console.log('✅ Adaptive payload generation passed (MySQL specific)');
    } else {
        console.log('❌ Adaptive payload generation failed');
    }

    // Test WAF Evasion
    const wafHints = ['WAF_TRIGGERED'];
    const xssPayload = getAdaptivePayload('XSS', wafHints, 'rvtok_123');
    console.log('Adaptive XSS Payload (WAF):', xssPayload);
    if (xssPayload.includes('svg') || xssPayload.includes('details')) {
        console.log('✅ WAF evasion payload passed');
    } else {
        console.log('❌ WAF evasion payload failed');
    }
}

async function run() {
    try {
        await testParamDiscovery();
        await testAdaptivePayloads();
        console.log('\n✨ ALL TESTS COMPLETED');
    } catch (err) {
        console.error('Tests failed:', err);
        process.exit(1);
    }
}

run();
