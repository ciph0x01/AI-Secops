#!/usr/bin/env node

const { spawn } = require('child_process');

async function testServer() {
  console.log('🧪 Testing MCP Security Inspector Server...');
  
  // Start server
  const server = spawn('node', ['server.js'], {
    stdio: ['pipe', 'pipe', 'pipe']
  });

  // Test initialize request
  const initRequest = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: {
        name: 'test-client',
        version: '1.0.0'
      }
    }
  };

  server.stdin.write(JSON.stringify(initRequest) + '\n');

  // Test tools/list request
  const toolsRequest = {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/list'
  };

  setTimeout(() => {
    server.stdin.write(JSON.stringify(toolsRequest) + '\n');
  }, 1000);

  // Listen for responses
  server.stdout.on('data', (data) => {
    const lines = data.toString().split('\n').filter(line => line.trim());
    lines.forEach(line => {
      try {
        const response = JSON.parse(line);
        console.log('✅ Response:', JSON.stringify(response, null, 2));
      } catch (error) {
        console.log('📝 Output:', line);
      }
    });
  });

  server.stderr.on('data', (data) => {
    console.log('📋 Server log:', data.toString());
  });

  // Close after 5 seconds
  setTimeout(() => {
    server.kill();
    console.log('🏁 Test completed');
  }, 5000);
}

testServer().catch(console.error);
