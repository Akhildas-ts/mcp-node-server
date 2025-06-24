// Replit-optimized MCP Agent Chat Server (Fixed for Go API)
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import express from 'express';
import cors from 'cors';
import axios from 'axios';
import 'dotenv/config';

const config = {
    GO_SERVER_URL: process.env.GO_SERVER_URL || process.env.GO_SERVER_HOST || 'https://your-go-server.repl.co',
    PORT: process.env.PORT || process.env.MCP_PORT || 3000,
    MCP_SECRET_TOKEN: process.env.MCP_SECRET_TOKEN,
    GO_AUTH_TOKEN: process.env.GO_AUTH_TOKEN,
    NODE_ENV: process.env.NODE_ENV || 'production'
  };
  
  console.log('🚀 Starting MCP Agent Chat Server');
  console.log('📍 Node.js Server Port:', config.PORT);
  console.log('🔗 Go Server URL:', config.GO_SERVER_URL);
  console.log('🌐 Environment:', config.NODE_ENV);
// Create Express app
const app = express();

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-MCP-Token']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Create MCP server instance
const mcpServer = new McpServer({
  name: 'mcp-agent-chat-replit',
  version: '1.0.0',
  description: 'MCP Agent Chat Server deployed on Replit (Go API Compatible)'
});

// Axios configuration for Go server
const goAxiosConfig = {
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    // Add authentication header if available
    ...(config.GO_AUTH_TOKEN && { 'Authorization': `Bearer ${config.GO_AUTH_TOKEN}` })
  }
};

// Auth state management (simple in-memory for demo)
let isAuthenticated = false;
let authToken = null;

// Authentication helper
async function ensureAuthenticated() {
  if (!isAuthenticated && !authToken) {
    throw new Error('Authentication required. Please authenticate with Go server first.');
  }
  return authToken;
}

// Health check endpoint - IMPORTANT for Replit
app.get('/', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'MCP Agent Chat Server',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: 'replit',
    go_server: config.GO_SERVER_URL
  });
});

app.get('/health', async (req, res) => {
  try {
    // Check Go server connection (public endpoint, no auth needed)
    const goServerResponse = await axios.get(`${config.GO_SERVER_URL}/health`, {
      timeout: 5000
    });
    
    res.json({
      status: 'healthy',
      mcp_server: 'running',
      go_server: 'connected',
      go_server_response: goServerResponse.data,
      authentication_status: isAuthenticated ? 'authenticated' : 'not_authenticated',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.json({
      status: 'partial',
      mcp_server: 'running',
      go_server: 'disconnected',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Authentication endpoints
app.get('/auth/status', (req, res) => {
  res.json({
    authenticated: isAuthenticated,
    has_token: !!authToken
  });
});

app.get('/auth/login', async (req, res) => {
  try {
    // Redirect to Go server login
    const loginUrl = `${config.GO_SERVER_URL}/auth/login`;
    res.redirect(loginUrl);
  } catch (error) {
    res.status(500).json({ error: 'Login failed', message: error.message });
  }
});

app.post('/auth/token', (req, res) => {
  const { token } = req.body;
  if (token) {
    authToken = token;
    isAuthenticated = true;
    goAxiosConfig.headers['Authorization'] = `Bearer ${token}`;
    res.json({ message: 'Authentication successful' });
  } else {
    res.status(400).json({ error: 'Token required' });
  }
});

// MCP Tools Configuration (Updated for Go API)
const tools = [
  {
    name: 'vector_search',
    description: 'Search code using vector similarity',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query' },
        repository: { type: 'string', description: 'Repository to search', optional: true },
        limit: { type: 'number', description: 'Max results', default: 5 }
      },
      required: ['query']
    }
  },
  {
    name: 'vector_search_summary',
    description: 'Search code with AI-generated summary',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query' },
        repository: { type: 'string', description: 'Repository to search', optional: true },
        limit: { type: 'number', description: 'Max results', default: 5 }
      },
      required: ['query']
    }
  },
  {
    name: 'index_repository',
    description: 'Index a repository for search',
    inputSchema: {
      type: 'object',
      properties: {
        repository: { type: 'string', description: 'Repository URL' },
        branch: { type: 'string', description: 'Branch name', default: 'main' }
      },
      required: ['repository']
    }
  },
  {
    name: 'get_repositories',
    description: 'Get list of indexed repositories',
    inputSchema: {
      type: 'object',
      properties: {}
    }
  }
];

// Register MCP tools (Updated for Go API endpoints)
mcpServer.tool('vector_search', {
  query: z.string(),
  repository: z.string().optional(),
  limit: z.number().optional()
}, async ({ query, repository, limit = 5 }) => {
  try {
    await ensureAuthenticated();
    
    const response = await axios.post(`${config.GO_SERVER_URL}/search`, {
      query,
      repository,
      limit
    }, goAxiosConfig);
    
    return {
      content: [{ type: 'text', text: JSON.stringify(response.data, null, 2) }]
    };
  } catch (error) {
    return {
      content: [{ type: 'text', text: `Vector search error: ${error.message}` }],
      isError: true
    };
  }
});

mcpServer.tool('vector_search_summary', {
  query: z.string(),
  repository: z.string().optional(),
  limit: z.number().optional()
}, async ({ query, repository, limit = 5 }) => {
  try {
    await ensureAuthenticated();
    
    const response = await axios.post(`${config.GO_SERVER_URL}/search/summary`, {
      query,
      repository,
      limit
    }, goAxiosConfig);
    
    return {
      content: [{ type: 'text', text: JSON.stringify(response.data, null, 2) }]
    };
  } catch (error) {
    return {
      content: [{ type: 'text', text: `Vector search with summary error: ${error.message}` }],
      isError: true
    };
  }
});

mcpServer.tool('index_repository', {
  repository: z.string(),
  branch: z.string().optional()
}, async ({ repository, branch = 'main' }) => {
  try {
    await ensureAuthenticated();
    
    const response = await axios.post(`${config.GO_SERVER_URL}/index`, {
      repository,
      branch
    }, goAxiosConfig);
    
    return {
      content: [{ type: 'text', text: JSON.stringify(response.data, null, 2) }]
    };
  } catch (error) {
    return {
      content: [{ type: 'text', text: `Index repository error: ${error.message}` }],
      isError: true
    };
  }
});

mcpServer.tool('get_repositories', {}, async () => {
  try {
    await ensureAuthenticated();
    
    const response = await axios.get(`${config.GO_SERVER_URL}/repositories`, goAxiosConfig);
    
    return {
      content: [{ type: 'text', text: JSON.stringify(response.data, null, 2) }]
    };
  } catch (error) {
    return {
      content: [{ type: 'text', text: `Get repositories error: ${error.message}` }],
      isError: true
    };
  }
});

// MCP endpoint for external clients
app.post('/mcp', async (req, res) => {
  try {
    console.log('📨 MCP request received:', req.body);
    
    if (!req.body.method) {
      return res.status(400).json({
        error: 'Missing method in MCP request'
      });
    }

    switch (req.body.method) {
      case 'tools/list':
        res.json({ tools: tools });
        break;
        
      case 'tools/call':
        const { name, arguments: args } = req.body.params;
        res.json({
          content: [{ type: 'text', text: `Tool ${name} called with args: ${JSON.stringify(args)}` }]
        });
        break;
        
      default:
        res.status(404).json({
          error: `Unknown MCP method: ${req.body.method}`
        });
    }
  } catch (error) {
    console.error('❌ MCP request error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// API endpoints for direct HTTP access (Updated for Go API)
app.post('/api/search', async (req, res) => {
  try {
    await ensureAuthenticated();
    const response = await axios.post(`${config.GO_SERVER_URL}/search`, req.body, goAxiosConfig);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/search/summary', async (req, res) => {
  try {
    await ensureAuthenticated();
    const response = await axios.post(`${config.GO_SERVER_URL}/search/summary`, req.body, goAxiosConfig);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/index', async (req, res) => {
  try {
    await ensureAuthenticated();
    const response = await axios.post(`${config.GO_SERVER_URL}/index`, req.body, goAxiosConfig);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/repositories', async (req, res) => {
  try {
    await ensureAuthenticated();
    const response = await axios.get(`${config.GO_SERVER_URL}/repositories`, goAxiosConfig);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Catch-all route
app.get('*', (req, res) => {
  res.json({
    message: 'MCP Agent Chat Server is running (Go API Compatible)',
    endpoints: {
      health: '/health',
      mcp: '/mcp',
      auth: '/auth/*',
      search: '/api/search',
      search_summary: '/api/search/summary',
      index: '/api/index',
      repositories: '/api/repositories'
    },
    authentication_required: true,
    go_server: config.GO_SERVER_URL
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('💥 Server error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: config.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// Start server
const server = app.listen(config.PORT, '0.0.0.0', () => {
  console.log(`✅ MCP Agent Chat Server running on port ${config.PORT}`);
  console.log(`🌐 Access URLs:`);
  console.log(`   - Health: http://localhost:${config.PORT}/health`);
  console.log(`   - MCP: http://localhost:${config.PORT}/mcp`);
  console.log(`   - API: http://localhost:${config.PORT}/api/*`);
  console.log(`🔐 Authentication required for Go server endpoints`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});