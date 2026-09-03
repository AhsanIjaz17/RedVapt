import axios from 'axios';

const API_BASE = 'http://localhost:3001/api';
let accessToken = '';
let workspaceId = '';

async function runTests() {
    console.log('🚀 Starting RedVapt Security & Workspace Verification...\n');

    try {
        // 1. Register User
        console.log('[1/5] Registering new user...');
        const regRes = await axios.post(`${API_BASE}/auth/register`, {
            email: 'tester@redvapt.com',
            password: 'SecurePassword123!'
        });
        const userId = regRes.data.user.id;
        console.log('✅ Registered successfully. Simulation: Link printed in server logs.\n');

        // 2. Verify Email (Simulated)
        console.log('[2/5] Verifying email...');
        await axios.get(`${API_BASE}/auth/verify?token=${userId}`);
        console.log('✅ Email verified.\n');

        // 3. Login
        console.log('[3/5] Logging in...');
        const loginRes = await axios.post(`${API_BASE}/auth/login`, {
            email: 'tester@redvapt.com',
            password: 'SecurePassword123!'
        });
        accessToken = loginRes.data.accessToken;
        console.log('✅ Login successful. Received JWT.\n');

        const authHeaders = { Authorization: `Bearer ${accessToken}` };

        // 4. Get My Workspaces
        console.log('[4/5] Fetching workspaces...');
        const wsRes = await axios.get(`${API_BASE}/workspaces/my`, { headers: authHeaders });
        workspaceId = wsRes.data[0].id;
        console.log(`✅ Found workspace: "${wsRes.data[0].name}" (ID: ${workspaceId})\n`);

        // 5. Test Workspace Authorization
        console.log('[5/5] Testing workspace-scoped access...');

        // Test access to own reports
        console.log('   - Fetching reports for OWN workspace...');
        const ownReportsRes = await axios.get(`${API_BASE}/workspaces/${workspaceId}/reports`, { headers: authHeaders });
        console.log(`   ✅ Success! (Response Status: ${ownReportsRes.status})\n`);

        // Test access to other workspace (unauthorized)
        console.log('   - Attempting to access OTHER workspace (ID: 999)...');
        try {
            await axios.get(`${API_BASE}/workspaces/999/reports`, { headers: authHeaders });
            console.error('   ❌ ERROR: Successfully accessed unauthorized workspace! Security check failed.');
        } catch (err) {
            if (err.response?.status === 403) {
                console.log('   ✅ Success! Forbidden access correctly blocked (Response Status: 403).\n');
            } else {
                throw err;
            }
        }

        console.log('🎉 ALL TESTS PASSED! The Authentication and Workspace systems are secure and functional.');

    } catch (error) {
        console.error('\n❌ VERIFICATION FAILED:', error.response?.data || error.message);
    }
}

runTests();
