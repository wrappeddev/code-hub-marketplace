// Cloudflare Worker for local testing with D1 and R2

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

// Handle CORS preflight requests
function handleCORS(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: corsHeaders,
    });
  }
  return null;
}

// Add CORS headers to response
function addCORSHeaders(response) {
  const newResponse = new Response(response.body, response);
  Object.entries(corsHeaders).forEach(([key, value]) => {
    newResponse.headers.set(key, value);
  });
  return newResponse;
}

// Discord OAuth initiation
async function handleDiscordAuth(request, env) {
  if (request.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const clientId = env.DISCORD_CLIENT_ID;

  // Get the page parameter to determine redirect URI
  const url = new URL(request.url);
  const page = url.searchParams.get('page') || 'submit';

  // Determine redirect URI based on the requesting page
  // Use environment variables if set, otherwise construct from current request URL
  let redirectUri;
  if (page === 'marketplace') {
    redirectUri = env.DISCORD_REDIRECT_URI_MARKETPLACE || `${url.protocol}//${url.host}/marketplace`;
  } else {
    redirectUri = env.DISCORD_REDIRECT_URI || `${url.protocol}//${url.host}/submit`;
  }

  if (!clientId) {
    return new Response(JSON.stringify({ error: 'Discord OAuth not configured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Generate a random state parameter for security
  const state = crypto.randomUUID();

  // Discord OAuth2 authorization URL
  const authUrl = new URL('https://discord.com/api/oauth2/authorize');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'identify email');
  authUrl.searchParams.set('state', state);

  return new Response(JSON.stringify({
    authUrl: authUrl.toString(),
    state: state,
    redirectUri: redirectUri
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

// Discord OAuth callback
async function handleDiscordCallback(request, env) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const body = await request.json();
  const { code, state, returnPage } = body;
  
  if (!code) {
    return new Response(JSON.stringify({ error: 'Authorization code is required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const clientId = env.DISCORD_CLIENT_ID;
  const clientSecret = env.DISCORD_CLIENT_SECRET;

  // Determine redirect URI based on returnPage or default to submit
  // Use environment variables if set, otherwise construct from current request URL
  const url = new URL(request.url);
  let redirectUri;
  if (returnPage === 'marketplace') {
    redirectUri = env.DISCORD_REDIRECT_URI_MARKETPLACE || `${url.protocol}//${url.host}/marketplace`;
  } else {
    redirectUri = env.DISCORD_REDIRECT_URI || `${url.protocol}//${url.host}/submit`;
  }

  if (!clientId || !clientSecret) {
    return new Response(JSON.stringify({ error: 'Discord OAuth not configured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Exchange authorization code for access token
  const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUri,
    }),
  });

  if (!tokenResponse.ok) {
    const errorData = await tokenResponse.text();
    console.error('Token exchange failed:', {
      status: tokenResponse.status,
      statusText: tokenResponse.statusText,
      error: errorData,
      redirectUri: redirectUri,
      clientId: clientId
    });
    return new Response(JSON.stringify({
      error: 'Failed to exchange authorization code',
      details: errorData,
      debug: {
        redirectUri: redirectUri,
        clientId: clientId
      }
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const tokenData = await tokenResponse.json();

  // Get user information from Discord
  const userResponse = await fetch('https://discord.com/api/users/@me', {
    headers: {
      'Authorization': `Bearer ${tokenData.access_token}`,
    },
  });

  if (!userResponse.ok) {
    return new Response(JSON.stringify({ error: 'Failed to get user information' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const userData = await userResponse.json();

  // Create a session token
  const sessionData = {
    userId: userData.id,
    username: userData.username,
    discriminator: userData.discriminator,
    avatar: userData.avatar,
    email: userData.email,
    timestamp: Date.now(),
  };

  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(sessionData));
  const sessionToken = btoa(String.fromCharCode(...data));

  return new Response(JSON.stringify({
    success: true,
    user: {
      id: userData.id,
      username: userData.username,
      discriminator: userData.discriminator,
      avatar: userData.avatar,
      email: userData.email,
    },
    sessionToken: sessionToken,
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

// Get authenticated user
async function handleGetUser(request, env) {
  if (request.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const authHeader = request.headers.get('authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'No authorization token provided' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const sessionToken = authHeader.substring(7);
  
  try {
    const decodedData = atob(sessionToken);
    const decoder = new TextDecoder();
    const userData = JSON.parse(decoder.decode(new Uint8Array([...decodedData].map(char => char.charCodeAt(0)))));
    
    // Check if token is expired (24 hours)
    const tokenAge = Date.now() - userData.timestamp;
    if (tokenAge > 24 * 60 * 60 * 1000) {
      return new Response(JSON.stringify({ error: 'Session expired' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({
      user: {
        id: userData.userId,
        username: userData.username,
        discriminator: userData.discriminator,
        avatar: userData.avatar,
        email: userData.email,
      },
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (decodeError) {
    return new Response(JSON.stringify({ error: 'Invalid session token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Check if user is admin
async function handleCheckAdmin(request, env) {
  if (request.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const authHeader = request.headers.get('authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'No authorization token provided' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const sessionToken = authHeader.substring(7);
    let userData;

    try {
      const decodedData = atob(sessionToken);
      const decoder = new TextDecoder();
      userData = JSON.parse(decoder.decode(new Uint8Array([...decodedData].map(char => char.charCodeAt(0)))));

      // Check if token is expired (24 hours)
      const tokenAge = Date.now() - userData.timestamp;
      if (tokenAge > 24 * 60 * 60 * 1000) {
        return new Response(JSON.stringify({ error: 'Session expired' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } catch (decodeError) {
      return new Response(JSON.stringify({ error: 'Invalid session token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Check if user ID is in admin list
    const adminIds = env.ADMIN_DISCORD_IDS ? env.ADMIN_DISCORD_IDS.split(',') : [];
    const isAdmin = adminIds.includes(userData.userId);

    // Debug logging
    console.log('Admin check debug:', {
      userId: userData.userId,
      adminIds: adminIds,
      isAdmin: isAdmin,
      adminIdsEnv: env.ADMIN_DISCORD_IDS
    });

    return new Response(JSON.stringify({
      isAdmin: isAdmin,
      userId: userData.userId,
      debug: {
        adminIds: adminIds,
        adminIdsEnv: env.ADMIN_DISCORD_IDS
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Check admin error:', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Update submission status
async function handleUpdateSubmissionStatus(request, env) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Verify admin authentication
    const authHeader = request.headers.get('authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const sessionToken = authHeader.substring(7);
    let userData;

    try {
      const decodedData = atob(sessionToken);
      const decoder = new TextDecoder();
      userData = JSON.parse(decoder.decode(new Uint8Array([...decodedData].map(char => char.charCodeAt(0)))));

      // Check if token is expired
      const tokenAge = Date.now() - userData.timestamp;
      if (tokenAge > 24 * 60 * 60 * 1000) {
        return new Response(JSON.stringify({ error: 'Session expired' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } catch (decodeError) {
      return new Response(JSON.stringify({ error: 'Invalid session token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Check if user is admin
    const adminIds = env.ADMIN_DISCORD_IDS ? env.ADMIN_DISCORD_IDS.split(',') : [];
    if (!adminIds.includes(userData.userId)) {
      return new Response(JSON.stringify({ error: 'Admin access required' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Parse request body
    const body = await request.json();
    const { submissionId, status } = body;

    if (!submissionId || !status) {
      return new Response(JSON.stringify({ error: 'Missing submissionId or status' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Validate status
    const validStatuses = ['pending', 'approved', 'rejected'];
    if (!validStatuses.includes(status)) {
      return new Response(JSON.stringify({ error: 'Invalid status' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Update submission in D1
    await env.DB.prepare(`
      UPDATE submissions
      SET status = ?
      WHERE id = ?
    `).bind(status, submissionId).run();

    return new Response(JSON.stringify({
      success: true,
      message: `Submission ${status} successfully`,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Update submission status error:', error);
    return new Response(JSON.stringify({
      error: 'Internal server error',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Delete submission
async function handleDeleteSubmission(request, env) {
  if (request.method !== 'DELETE') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Verify admin authentication
    const authHeader = request.headers.get('authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const sessionToken = authHeader.substring(7);
    let userData;

    try {
      const decodedData = atob(sessionToken);
      const decoder = new TextDecoder();
      userData = JSON.parse(decoder.decode(new Uint8Array([...decodedData].map(char => char.charCodeAt(0)))));

      // Check if token is expired
      const tokenAge = Date.now() - userData.timestamp;
      if (tokenAge > 24 * 60 * 60 * 1000) {
        return new Response(JSON.stringify({ error: 'Session expired' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } catch (decodeError) {
      return new Response(JSON.stringify({ error: 'Invalid session token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Check if user is admin
    const adminIds = env.ADMIN_DISCORD_IDS ? env.ADMIN_DISCORD_IDS.split(',') : [];
    if (!adminIds.includes(userData.userId)) {
      return new Response(JSON.stringify({ error: 'Admin access required' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Get submission ID from URL
    const url = new URL(request.url);
    const submissionId = url.searchParams.get('id');

    if (!submissionId) {
      return new Response(JSON.stringify({ error: 'Missing submission ID' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Get submission details first (for cleanup)
    const submission = await env.DB.prepare(`
      SELECT * FROM submissions WHERE id = ?
    `).bind(submissionId).first();

    if (!submission) {
      return new Response(JSON.stringify({ error: 'Submission not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Delete associated images from R2 if they exist
    if (submission.images) {
      try {
        const images = JSON.parse(submission.images);
        for (const image of images) {
          if (image.r2Key) {
            await env.UPLOADS.delete(image.r2Key);
          }
        }
      } catch (imageError) {
        console.error('Error deleting images:', imageError);
        // Continue with submission deletion even if image cleanup fails
      }
    }

    // Delete submission from D1
    await env.DB.prepare(`
      DELETE FROM submissions WHERE id = ?
    `).bind(submissionId).run();

    return new Response(JSON.stringify({
      success: true,
      message: 'Submission deleted successfully',
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Delete submission error:', error);
    return new Response(JSON.stringify({
      error: 'Internal server error',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Get comments for a submission
async function handleGetComments(request, env) {
  if (request.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const url = new URL(request.url);
    const submissionId = url.searchParams.get('submissionId');

    if (!submissionId) {
      return new Response(JSON.stringify({ error: 'Missing submission ID' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Get comments from D1
    const result = await env.DB.prepare(`
      SELECT * FROM comments
      WHERE submission_id = ?
      ORDER BY created_at DESC
    `).bind(submissionId).all();

    const comments = result.results.map(row => ({
      id: row.id,
      submissionId: row.submission_id,
      content: row.content,
      rating: row.rating || null,
      authorId: row.author_id || row.user_id,
      authorUsername: row.author_username || 'Unknown User',
      authorDiscriminator: row.author_discriminator || '0000',
      createdAt: row.created_at,
    }));

    return new Response(JSON.stringify({
      success: true,
      comments: comments,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Get comments error:', error);
    return new Response(JSON.stringify({
      error: 'Internal server error',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Add a comment to a submission
async function handleAddComment(request, env) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Verify authentication
    const authHeader = request.headers.get('authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const sessionToken = authHeader.substring(7);
    let userData;

    try {
      const decodedData = atob(sessionToken);
      const decoder = new TextDecoder();
      userData = JSON.parse(decoder.decode(new Uint8Array([...decodedData].map(char => char.charCodeAt(0)))));

      // Check if token is expired (24 hours)
      const tokenAge = Date.now() - userData.timestamp;
      if (tokenAge > 24 * 60 * 60 * 1000) {
        return new Response(JSON.stringify({ error: 'Session expired' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } catch (decodeError) {
      return new Response(JSON.stringify({ error: 'Invalid session token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Check if user is banned
    const bannedUser = await env.DB.prepare(`
      SELECT * FROM banned_users WHERE user_id = ?
    `).bind(userData.userId).first();

    if (bannedUser) {
      return new Response(JSON.stringify({
        error: 'You have been banned from commenting',
        reason: bannedUser.reason || 'No reason provided'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Parse request body
    const body = await request.json();
    const { submissionId, content, rating } = body;

    if (!submissionId || !content) {
      return new Response(JSON.stringify({ error: 'Missing required fields' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Validate rating (1-5 stars)
    if (rating && (rating < 1 || rating > 5)) {
      return new Response(JSON.stringify({ error: 'Rating must be between 1 and 5' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Check if submission exists and is approved
    const submission = await env.DB.prepare(`
      SELECT * FROM submissions WHERE id = ? AND status = 'approved'
    `).bind(submissionId).first();

    if (!submission) {
      return new Response(JSON.stringify({ error: 'Submission not found or not approved' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Create comment
    const commentId = `CMT_${Date.now()}_${crypto.randomUUID()}`;

    // Try to insert with the expected schema first, fallback to alternative schema
    try {
      await env.DB.prepare(`
        INSERT INTO comments (
          id, submission_id, content, rating, author_id, author_username,
          author_discriminator, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        commentId,
        submissionId,
        content,
        rating || null,
        userData.userId,
        userData.username,
        userData.discriminator,
        new Date().toISOString()
      ).run();
    } catch (error) {
      // If the above fails, try with the alternative schema (user_id instead of author_id, etc.)
      console.log('Trying alternative comments schema...', error.message);
      await env.DB.prepare(`
        INSERT INTO comments (
          submission_id, user_id, content, created_at
        ) VALUES (?, ?, ?, ?)
      `).bind(
        submissionId,
        userData.userId,
        content,
        new Date().toISOString()
      ).run();
    }

    return new Response(JSON.stringify({
      success: true,
      message: 'Comment added successfully',
      commentId: commentId,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Add comment error:', error);
    return new Response(JSON.stringify({
      error: 'Internal server error',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Delete a comment (admin only)
async function handleDeleteComment(request, env) {
  if (request.method !== 'DELETE') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Verify admin authentication
    const authHeader = request.headers.get('authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const sessionToken = authHeader.substring(7);
    let userData;

    try {
      const decodedData = atob(sessionToken);
      const decoder = new TextDecoder();
      userData = JSON.parse(decoder.decode(new Uint8Array([...decodedData].map(char => char.charCodeAt(0)))));

      // Check if token is expired
      const tokenAge = Date.now() - userData.timestamp;
      if (tokenAge > 24 * 60 * 60 * 1000) {
        return new Response(JSON.stringify({ error: 'Session expired' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } catch (decodeError) {
      return new Response(JSON.stringify({ error: 'Invalid session token' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Check if user is admin
    const adminIds = env.ADMIN_DISCORD_IDS ? env.ADMIN_DISCORD_IDS.split(',') : [];
    if (!adminIds.includes(userData.userId)) {
      return new Response(JSON.stringify({ error: 'Admin access required' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Get comment ID from URL
    const url = new URL(request.url);
    const commentId = url.searchParams.get('id');

    if (!commentId) {
      return new Response(JSON.stringify({ error: 'Missing comment ID' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Delete comment from D1
    const result = await env.DB.prepare(`
      DELETE FROM comments WHERE id = ?
    `).bind(commentId).run();

    if (result.changes === 0) {
      return new Response(JSON.stringify({ error: 'Comment not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({
      success: true,
      message: 'Comment deleted successfully',
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Delete comment error:', error);
    return new Response(JSON.stringify({
      error: 'Internal server error',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Handle ban user
async function handleBanUser(request, env) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Verify admin authentication
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const token = authHeader.substring(7);
    const userData = await verifySessionToken(token, env);

    if (!userData) {
      return new Response(JSON.stringify({ error: 'Invalid session' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Check if user is admin
    const adminIds = env.ADMIN_DISCORD_IDS.split(',');
    if (!adminIds.includes(userData.userId)) {
      return new Response(JSON.stringify({ error: 'Admin access required' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Parse request body
    const body = await request.json();
    const { userId, username, discriminator, reason } = body;

    if (!userId || !username || !discriminator) {
      return new Response(JSON.stringify({ error: 'Missing required fields' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Check if user is already banned
    const existingBan = await env.DB.prepare(`
      SELECT * FROM banned_users WHERE user_id = ?
    `).bind(userId).first();

    if (existingBan) {
      return new Response(JSON.stringify({ error: 'User is already banned' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Add user to banned list
    const banId = crypto.randomUUID();
    await env.DB.prepare(`
      INSERT INTO banned_users (id, user_id, username, discriminator, banned_by, banned_at, reason)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      banId,
      userId,
      username,
      discriminator,
      userData.userId,
      new Date().toISOString(),
      reason || 'No reason provided'
    ).run();

    return new Response(JSON.stringify({
      success: true,
      message: 'User banned successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error banning user:', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Handle get banned users
async function handleGetBannedUsers(request, env) {
  if (request.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    // Verify admin authentication
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const token = authHeader.substring(7);
    const userData = await verifySessionToken(token, env);

    if (!userData) {
      return new Response(JSON.stringify({ error: 'Invalid session' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Check if user is admin
    const adminIds = env.ADMIN_DISCORD_IDS.split(',');
    if (!adminIds.includes(userData.userId)) {
      return new Response(JSON.stringify({ error: 'Admin access required' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Get banned users
    const bannedUsers = await env.DB.prepare(`
      SELECT * FROM banned_users ORDER BY banned_at DESC
    `).all();

    return new Response(JSON.stringify({
      success: true,
      bannedUsers: bannedUsers.results || []
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error getting banned users:', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Get submissions from D1
async function handleGetSubmissions(request, env) {
  if (request.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const url = new URL(request.url);
    const status = url.searchParams.get('status') || 'approved';
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const includeStats = url.searchParams.get('stats') === 'true';

    // Query submissions from D1
    const query = status === 'all'
      ? `SELECT * FROM submissions ORDER BY submitted_at DESC LIMIT ? OFFSET ?`
      : `SELECT * FROM submissions WHERE status = ? ORDER BY submitted_at DESC LIMIT ? OFFSET ?`;

    const params = status === 'all' ? [limit, offset] : [status, limit, offset];

    const result = await env.DB.prepare(query).bind(...params).all();

    const submissions = result.results.map(row => ({
      id: row.id,
      commandCode: row.command_code,
      commandName: row.command_name,
      commandDescription: row.command_description,
      commandCategory: row.command_category || 'other',
      submittedBy: {
        userId: row.submitted_by_user_id,
        username: row.submitted_by_username,
        discriminator: row.submitted_by_discriminator,
      },
      images: row.images ? JSON.parse(row.images) : [],
      submittedAt: row.submitted_at,
      status: row.status,
    }));

    let stats = null;
    if (includeStats) {
      const statsResult = await env.DB.prepare(`
        SELECT status, COUNT(*) as count
        FROM submissions
        GROUP BY status
      `).all();

      stats = {};
      statsResult.results.forEach(row => {
        stats[row.status] = row.count;
      });
    }

    return new Response(JSON.stringify({
      success: true,
      submissions: submissions,
      pagination: {
        limit: limit,
        offset: offset,
        count: submissions.length,
      },
      stats: stats,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Get submissions error:', error);
    return new Response(JSON.stringify({
      error: 'Internal server error',
      message: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Submit command with D1 and R2
async function handleSubmitCommand(request, env) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Verify authentication
  const authHeader = request.headers.get('authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'Authentication required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const sessionToken = authHeader.substring(7);
  let userData;
  
  try {
    const decodedData = atob(sessionToken);
    const decoder = new TextDecoder();
    userData = JSON.parse(decoder.decode(new Uint8Array([...decodedData].map(char => char.charCodeAt(0)))));
    
    // Check if token is expired (24 hours)
    const tokenAge = Date.now() - userData.timestamp;
    if (tokenAge > 24 * 60 * 60 * 1000) {
      return new Response(JSON.stringify({ error: 'Session expired' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  } catch (decodeError) {
    return new Response(JSON.stringify({ error: 'Invalid session token' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Parse form data
  const formData = await request.formData();
  const commandCode = formData.get('commandCode');
  const commandName = formData.get('commandName');
  const commandDescription = formData.get('commandDescription');
  const commandCategory = formData.get('commandCategory');

  // Validate required fields
  if (!commandCode || !commandName || !commandDescription || !commandCategory) {
    return new Response(JSON.stringify({
      error: 'Missing required fields: commandCode, commandName, commandDescription, commandCategory'
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Validate command code format
  if (!commandCode.startsWith('CMD_') || commandCode.length < 20) {
    return new Response(JSON.stringify({ 
      error: 'Invalid command code format. Must start with CMD_ and be at least 20 characters long.' 
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // Handle image uploads to R2
  const uploadedImages = [];
  const imageFiles = formData.getAll('images');
  
  for (const file of imageFiles) {
    if (file && file.size > 0) {
      const fileName = `submissions/${Date.now()}_${crypto.randomUUID()}_${file.name}`;
      
      try {
        await env.UPLOADS.put(fileName, file.stream(), {
          httpMetadata: {
            contentType: file.type,
          },
        });
        
        uploadedImages.push({
          filename: file.name,
          contentType: file.type,
          size: file.size,
          r2Key: fileName,
          url: `https://your-r2-domain.com/${fileName}`, // Replace with your R2 domain
        });
      } catch (uploadError) {
        console.error('R2 upload error:', uploadError);
        return new Response(JSON.stringify({ 
          error: `Failed to upload image: ${file.name}` 
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }
  }

  // Save to D1 database
  const submissionId = `SUB_${Date.now()}_${crypto.randomUUID()}`;
  
  try {
    await env.DB.prepare(`
      INSERT INTO submissions (
        id, command_code, command_name, command_description, command_category,
        submitted_by_user_id, submitted_by_username, submitted_by_discriminator,
        images, submitted_at, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      submissionId,
      commandCode,
      commandName,
      commandDescription,
      commandCategory,
      userData.userId,
      userData.username,
      userData.discriminator,
      JSON.stringify(uploadedImages),
      new Date().toISOString(),
      'pending'
    ).run();

    return new Response(JSON.stringify({
      success: true,
      message: 'Command submitted successfully!',
      submissionId: submissionId,
      imagesUploaded: uploadedImages.length,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (dbError) {
    console.error('D1 save error:', dbError);
    return new Response(JSON.stringify({ 
      error: 'Failed to save submission to database' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Serve static files
async function serveStaticFile(path) {
  // Handle route aliases
  if (path === '/submit') {
    path = '/submit.html';
  }

  // Professional Code Hub UI
  const staticFiles = {
    '/marketplace': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Marketplace - Code Hub</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            line-height: 1.6;
        }

        /* Header */
        .header {
            background: rgba(10, 10, 10, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid #1a1a1a;
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .nav {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 2rem;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: #ffffff;
            text-decoration: none;
        }

        .logo-icon {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, #ffffff, #cccccc);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            color: #000;
        }

        .nav-links {
            display: flex;
            gap: 2rem;
            list-style: none;
        }

        .nav-links a {
            color: #cccccc;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }

        .nav-links a:hover, .nav-links a.active {
            color: #ffffff;
        }

        .user-nav {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-info-card {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 0.5rem 1rem;
        }

        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            border: 2px solid rgba(255, 255, 255, 0.2);
        }

        .user-details {
            display: flex;
            flex-direction: column;
            gap: 0.125rem;
        }

        .user-name {
            font-size: 0.875rem;
            font-weight: 600;
            color: #ffffff;
        }

        .user-status {
            font-size: 0.75rem;
            color: #888888;
        }

        .logout-btn {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #ef4444;
            padding: 0.375rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.375rem;
        }

        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.2);
            border-color: rgba(239, 68, 68, 0.5);
        }

        /* Main Content */
        .main {
            max-width: 1200px;
            margin: 0 auto;
            padding: 3rem 2rem;
        }

        .page-header {
            text-align: center;
            margin-bottom: 3rem;
        }

        .page-title {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #ffffff, #cccccc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .page-subtitle {
            font-size: 1.125rem;
            color: #cccccc;
            max-width: 600px;
            margin: 0 auto;
        }

        /* Search and Filters */
        .search-section {
            background: linear-gradient(135deg, #1a1a1a, #0f0f0f);
            border: 1px solid #2a2a2a;
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 3rem;
        }

        .search-bar {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .search-input {
            flex: 1;
            padding: 1rem;
            border: 1px solid #2a2a2a;
            background: #111111;
            color: #ffffff;
            border-radius: 12px;
            font-size: 1rem;
        }

        .search-btn {
            padding: 1rem 2rem;
            background: #ffffff;
            color: #000000;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .search-btn:hover {
            background: #f0f0f0;
        }

        .filters {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 0.5rem 1rem;
            background: transparent;
            color: #cccccc;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .filter-btn:hover, .filter-btn.active {
            background: #ffffff;
            color: #000000;
            border-color: #ffffff;
        }

        /* Commands Grid */
        .commands-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 2rem;
        }

        .command-card {
            background: linear-gradient(135deg, #1a1a1a, #0f0f0f);
            border: 1px solid #2a2a2a;
            border-radius: 16px;
            padding: 1.5rem;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .command-card:hover {
            transform: translateY(-5px);
            border-color: #3a3a3a;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }

        .command-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }

        .command-name {
            font-size: 1.25rem;
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 0.25rem;
        }

        .command-category {
            font-size: 0.875rem;
            color: #888888;
            background: rgba(255, 255, 255, 0.1);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }

        .command-description {
            color: #cccccc;
            margin-bottom: 1rem;
            line-height: 1.5;
        }

        .command-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-top: 1rem;
            border-top: 1px solid #2a2a2a;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .command-author {
            font-size: 0.875rem;
            color: #888888;
            flex: 1;
            min-width: 0;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .command-actions {
            display: flex;
            gap: 0.5rem;
            flex-shrink: 0;
        }

        .copy-btn {
            padding: 0.5rem 1rem;
            background: #ffffff;
            color: #000000;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .copy-btn:hover {
            background: #f0f0f0;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 4rem 2rem;
            color: #666666;
        }

        .empty-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }

        /* Loading */
        .loading {
            text-align: center;
            padding: 4rem 2rem;
        }

        .spinner {
            display: inline-block;
            width: 40px;
            height: 40px;
            border: 3px solid #333333;
            border-top: 3px solid #ffffff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Modal */
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }

        .modal.hidden {
            display: none !important;
        }

        .modal-content {
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 16px;
            padding: 2rem;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .close-btn {
            background: none;
            border: none;
            color: #888888;
            font-size: 1.5rem;
            cursor: pointer;
        }

        .close-btn:hover {
            color: #ffffff;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .nav {
                padding: 0 1rem;
            }

            .nav-links {
                display: none;
            }

            .main {
                padding: 2rem 1rem;
            }

            .search-bar {
                flex-direction: column;
            }

            .commands-grid {
                grid-template-columns: 1fr;
            }

            .command-footer {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.75rem;
            }

            .command-author {
                white-space: normal;
                text-overflow: unset;
                overflow: visible;
            }

            .command-actions {
                width: 100%;
                justify-content: flex-end;
            }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <nav class="nav">
            <a href="/" class="logo">
                <div class="logo-icon">
                    <i class="fas fa-code"></i>
                </div>
                Code Hub
            </a>
            <ul class="nav-links">
                <li><a href="/">Features</a></li>
                <li><a href="/marketplace" class="active">Marketplace</a></li>
                <li><a href="/submit">Submit</a></li>
                <li><a href="/docs">Documentation</a></li>
            </ul>
            <div class="user-nav">
                <div id="user-info" class="user-info-card hidden">
                    <img id="user-avatar" class="user-avatar" alt="User Avatar">
                    <div class="user-details">
                        <div id="user-name" class="user-name"></div>
                        <div class="user-status">Authenticated</div>
                    </div>
                    <button id="logout-btn" class="logout-btn">
                        <i class="fas fa-sign-out-alt"></i>
                        Logout
                    </button>
                </div>
            </div>
        </nav>
    </header>

    <!-- Main Content -->
    <main class="main">
        <div class="page-header">
            <h1 class="page-title">BotGhost Command Marketplace</h1>
            <p class="page-subtitle">Discover and import community-created BotGhost commands. Find the perfect commands for your Discord bot.</p>
        </div>

        <!-- Search and Filters -->
        <div class="search-section">
            <div class="search-bar">
                <input type="text" class="search-input" placeholder="Search commands..." id="search-input">
                <button class="search-btn" onclick="searchCommands()">
                    <i class="fas fa-search"></i>
                    Search
                </button>
            </div>
            <div class="filters">
                <button class="filter-btn active" data-category="all">All</button>
                <button class="filter-btn" data-category="moderation">Moderation</button>
                <button class="filter-btn" data-category="fun">Fun</button>
                <button class="filter-btn" data-category="utility">Utility</button>
                <button class="filter-btn" data-category="economy">Economy</button>
                <button class="filter-btn" data-category="music">Music</button>
                <button class="filter-btn" data-category="games">Games</button>
            </div>
        </div>

        <!-- Commands Grid -->
        <div id="commands-container">
            <div class="loading">
                <div class="spinner"></div>
                <p style="margin-top: 1rem; color: #cccccc;">Loading commands...</p>
            </div>
        </div>
    </main>

    <script>
        let allCommands = [];
        let filteredCommands = [];
        let currentCategory = 'all';

        // Load commands on page load
        document.addEventListener('DOMContentLoaded', loadCommands);

        // Event delegation for copy buttons
        document.addEventListener('click', (e) => {
            if (e.target.closest('.copy-btn')) {
                e.preventDefault();
                copyCommand(e.target.closest('.copy-btn'));
            }
        });

        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentCategory = btn.dataset.category;
                filterCommands();
            });
        });

        // Search input
        document.getElementById('search-input').addEventListener('input', searchCommands);

        async function loadCommands() {
            try {
                const response = await fetch('/api/get-submissions?status=approved');
                const data = await response.json();

                if (data.success) {
                    allCommands = data.submissions;
                    filteredCommands = [...allCommands];
                    renderCommands();
                } else {
                    showEmptyState();
                }
            } catch (error) {
                console.error('Error loading commands:', error);
                showEmptyState();
            }
        }

        function filterCommands() {
            if (currentCategory === 'all') {
                filteredCommands = [...allCommands];
            } else {
                filteredCommands = allCommands.filter(cmd =>
                    cmd.commandName.toLowerCase().includes(currentCategory) ||
                    cmd.commandDescription.toLowerCase().includes(currentCategory)
                );
            }

            const searchTerm = document.getElementById('search-input').value.toLowerCase();
            if (searchTerm) {
                filteredCommands = filteredCommands.filter(cmd =>
                    cmd.commandName.toLowerCase().includes(searchTerm) ||
                    cmd.commandDescription.toLowerCase().includes(searchTerm)
                );
            }

            renderCommands();
        }

        function searchCommands() {
            filterCommands();
        }

        function renderCommands() {
            const container = document.getElementById('commands-container');

            if (filteredCommands.length === 0) {
                showEmptyState();
                return;
            }

            const grid = document.createElement('div');
            grid.className = 'commands-grid';

            filteredCommands.forEach(command => {
                const card = createCommandCard(command);
                grid.appendChild(card);
            });

            container.innerHTML = '';
            container.appendChild(grid);
        }

        function createCommandCard(command) {
            const card = document.createElement('div');
            card.className = 'command-card';

            const category = guessCategory(command.commandName, command.commandDescription);

            card.innerHTML = '<div class="command-header">' +
                    '<div>' +
                        '<div class="command-name">' + command.commandName + '</div>' +
                    '</div>' +
                    '<div class="command-category">' + category + '</div>' +
                '</div>' +
                '<div class="command-description">' + command.commandDescription + '</div>' +
                '<div class="command-footer">' +
                    '<div class="command-author">by ' + command.submittedBy.username + '</div>' +
                    '<div class="command-actions">' +
                        '<button class="view-details-btn" onclick="viewCommandDetails(&quot;' + command.id + '&quot;)" style="background: #3b82f6; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; margin-right: 0.5rem; cursor: pointer;">' +
                            '<i class="fas fa-eye"></i> Details' +
                        '</button>' +
                        '<button class="copy-btn" data-command-code="' + command.commandCode.replace(/"/g, '&quot;') + '">' +
                            '<i class="fas fa-copy"></i> Copy Code' +
                        '</button>' +
                    '</div>' +
                '</div>';

            return card;
        }

        function guessCategory(name, description) {
            const text = (name + ' ' + description).toLowerCase();

            if (text.includes('mod') || text.includes('ban') || text.includes('kick') || text.includes('warn')) return 'Moderation';
            if (text.includes('fun') || text.includes('joke') || text.includes('meme') || text.includes('game')) return 'Fun';
            if (text.includes('music') || text.includes('play') || text.includes('song')) return 'Music';
            if (text.includes('economy') || text.includes('money') || text.includes('coin') || text.includes('shop')) return 'Economy';
            if (text.includes('util') || text.includes('info') || text.includes('help')) return 'Utility';

            return 'General';
        }

        function copyCommand(btn) {
            const commandCode = btn.getAttribute('data-command-code');
            const card = btn.closest('.command-card');
            const commandName = card.querySelector('.command-name').textContent;

            navigator.clipboard.writeText(commandCode).then(() => {
                // Show custom copy modal
                showCopyModal(commandName);
            }).catch(err => {
                console.error('Failed to copy:', err);
                alert('Failed to copy command code. Please try again.');
            });
        }

        function showEmptyState() {
            const container = document.getElementById('commands-container');
            container.innerHTML = '<div class="empty-state">' +
                '<div class="empty-icon">' +
                    '<i class="fas fa-search"></i>' +
                '</div>' +
                '<h3 style="color: #cccccc; margin-bottom: 1rem;">No commands found</h3>' +
                '<p>Be the first to share a BotGhost command!</p>' +
                '<a href="/submit.html" style="display: inline-block; margin-top: 1rem; padding: 1rem 2rem; background: #ffffff; color: #000000; text-decoration: none; border-radius: 12px; font-weight: 600;">' +
                    'Submit a Command' +
                '</a>' +
            '</div>';
        }

        function showCopyModal(commandName) {
            const copyModal = document.getElementById('copy-modal');
            const copyModalBody = document.getElementById('copy-modal-body');

            copyModalBody.innerHTML = '<div style="padding: 2rem 1rem; text-align: center;">' +
                '<div style="font-size: 4rem; color: #22c55e; margin-bottom: 1rem;">' +
                    '<i class="fas fa-check-circle"></i>' +
                '</div>' +
                '<h3 style="color: #ffffff; margin-bottom: 1rem; font-size: 1.5rem;">Command Copied!</h3>' +
                '<p style="color: #cccccc; margin-bottom: 2rem; line-height: 1.6;">' +
                    '"' + commandName + '" has been copied to your clipboard. You can now import it into BotGhost.' +
                '</p>' +
                '<button onclick="closeCopyModal()" class="action-btn" style="background: #22c55e; color: white; padding: 0.75rem 2rem; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;">' +
                    '<i class="fas fa-check"></i> Got it' +
                '</button>' +
            '</div>';

            copyModal.classList.remove('hidden');
            copyModal.style.display = 'flex';
        }

        function closeCopyModal() {
            const copyModal = document.getElementById('copy-modal');
            copyModal.classList.add('hidden');
            copyModal.style.display = 'none';
            document.getElementById('copy-modal-body').innerHTML = '';
        }

        // Command details modal functions
        async function viewCommandDetails(commandId) {
            const command = allCommands.find(cmd => cmd.id === commandId);
            if (!command) return;

            const modal = document.getElementById('command-details-modal');
            const modalBody = document.getElementById('command-details-body');

            // Load comments for this command
            let comments = [];
            try {
                const response = await fetch('/api/comments?submissionId=' + commandId);
                const data = await response.json();
                if (data.success) {
                    comments = data.comments;
                }
            } catch (error) {
                console.error('Error loading comments:', error);
            }

            const category = command.commandCategory || guessCategory(command.commandName, command.commandDescription);

            // Build the modal content
            let modalContent = '<div class="command-details-content">';

            // Command info section
            modalContent += '<div class="command-info">';
            modalContent += '<h4 style="color: #ffffff; margin-bottom: 0.5rem;">Command Name</h4>';
            modalContent += '<p style="color: #cccccc; margin-bottom: 1rem;">' + command.commandName + '</p>';
            modalContent += '<h4 style="color: #ffffff; margin-bottom: 0.5rem;">Category</h4>';
            modalContent += '<p style="color: #cccccc; margin-bottom: 1rem;">' + category + '</p>';
            modalContent += '<h4 style="color: #ffffff; margin-bottom: 0.5rem;">Description</h4>';
            modalContent += '<p style="color: #cccccc; margin-bottom: 1rem;">' + command.commandDescription + '</p>';
            modalContent += '<h4 style="color: #ffffff; margin-bottom: 0.5rem;">Created By</h4>';
            modalContent += '<p style="color: #cccccc; margin-bottom: 1rem;">' + command.submittedBy.username + '#' + command.submittedBy.discriminator + '</p>';
            modalContent += '<h4 style="color: #ffffff; margin-bottom: 0.5rem;">Command Code</h4>';
            modalContent += '<div style="background: #111111; border: 1px solid #2a2a2a; border-radius: 8px; padding: 1rem; font-family: monospace; font-size: 0.875rem; color: #ffffff; word-break: break-all; max-height: 200px; overflow-y: auto; margin-bottom: 2rem;">';
            modalContent += command.commandCode;
            modalContent += '</div>';
            modalContent += '<button id="copy-command-btn" data-command-code="' + command.commandCode.replace(/"/g, '&quot;') + '" style="background: #22c55e; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; cursor: pointer; font-weight: 600; margin-bottom: 2rem;">';
            modalContent += '<i class="fas fa-copy"></i> Copy Command Code';
            modalContent += '</button>';
            modalContent += '</div>';

            // Comments section
            modalContent += '<div class="comments-section">';
            modalContent += '<h4 style="color: #ffffff; margin-bottom: 1rem;">Comments & Reviews</h4>';

            // Add comment form
            modalContent += '<div id="add-comment-form" style="background: #111111; border: 1px solid #2a2a2a; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem;">';
            modalContent += '<h5 style="color: #ffffff; margin-bottom: 1rem;">Add a Comment</h5>';

            // Check if user is logged in
            const sessionToken = localStorage.getItem('sessionToken');
            if (!sessionToken) {
                modalContent += '<div style="text-align: center; padding: 2rem;">';
                modalContent += '<div style="background: #111111; border: 1px solid #2a2a2a; border-radius: 8px; padding: 2rem;">';
                modalContent += '<div style="font-size: 2rem; margin-bottom: 1rem;">💬</div>';
                modalContent += '<h4 style="color: #ffffff; margin-bottom: 1rem;">Join the Conversation</h4>';
                modalContent += '<p style="color: #cccccc; margin-bottom: 1.5rem; line-height: 1.6;">Share your thoughts and help others by posting a review or comment.</p>';
                modalContent += '<button id="marketplace-discord-login" style="display: inline-block; padding: 0.75rem 1.5rem; background: #5865f2; color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 0.5rem; margin: 0 auto;">';
                modalContent += '<i class="fab fa-discord"></i> Login with Discord';
                modalContent += '</button>';
                modalContent += '</div>';
                modalContent += '</div>';
            } else {
                modalContent += '<div style="margin-bottom: 1rem;">';
                modalContent += '<label style="color: #cccccc; display: block; margin-bottom: 0.5rem;">Rating (optional)</label>';
                modalContent += '<div class="star-rating" style="margin-bottom: 1rem;">';
                modalContent += '<span class="star" data-rating="1" style="cursor: pointer; font-size: 1.5rem; margin-right: 0.25rem;">⭐</span>';
                modalContent += '<span class="star" data-rating="2" style="cursor: pointer; font-size: 1.5rem; margin-right: 0.25rem;">⭐</span>';
                modalContent += '<span class="star" data-rating="3" style="cursor: pointer; font-size: 1.5rem; margin-right: 0.25rem;">⭐</span>';
                modalContent += '<span class="star" data-rating="4" style="cursor: pointer; font-size: 1.5rem; margin-right: 0.25rem;">⭐</span>';
                modalContent += '<span class="star" data-rating="5" style="cursor: pointer; font-size: 1.5rem; margin-right: 0.25rem;">⭐</span>';
                modalContent += '</div>';
                modalContent += '</div>';
                modalContent += '<textarea id="comment-text" placeholder="Share your thoughts about this command..." style="width: 100%; padding: 1rem; background: #0a0a0a; border: 1px solid #2a2a2a; border-radius: 6px; color: #ffffff; resize: vertical; min-height: 100px; margin-bottom: 1rem;"></textarea>';
                modalContent += '<button id="submit-comment-btn" data-command-id="' + commandId + '" style="background: #3b82f6; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 6px; cursor: pointer; font-weight: 600;">';
                modalContent += '<i class="fas fa-comment"></i> Post Comment';
                modalContent += '</button>';
            }
            modalContent += '</div>';

            // Comments list
            modalContent += '<div id="comments-list">';
            if (comments.length === 0) {
                modalContent += '<p style="color: #888888; text-align: center; padding: 2rem;">No comments yet. Be the first to share your thoughts!</p>';
            } else {
                for (let i = 0; i < comments.length; i++) {
                    const comment = comments[i];
                    modalContent += '<div class="comment" style="background: #111111; border: 1px solid #2a2a2a; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem;">';
                    modalContent += '<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">';
                    modalContent += '<div>';
                    modalContent += '<div style="color: #ffffff; font-weight: 600;">' + comment.authorUsername + '#' + comment.authorDiscriminator + '</div>';
                    modalContent += '<div style="color: #888888; font-size: 0.875rem;">' + new Date(comment.createdAt).toLocaleDateString() + '</div>';
                    if (comment.rating) {
                        modalContent += '<div style="color: #fbbf24; margin-top: 0.25rem;">' + '⭐'.repeat(comment.rating) + '</div>';
                    }
                    modalContent += '</div>';
                    modalContent += '<div style="display: flex; gap: 0.5rem;">';
                    modalContent += '<div style="display: flex; gap: 0.25rem;">';
                    modalContent += '<button class="delete-comment-btn" data-comment-id="' + comment.id + '" style="background: #ef4444; color: white; border: none; padding: 0.25rem 0.5rem; border-radius: 4px; cursor: pointer; font-size: 0.75rem;" title="Delete comment (Admin only)">';
                    modalContent += '<i class="fas fa-trash"></i>';
                    modalContent += '</button>';
                    modalContent += '<button class="ban-user-btn" data-user-id="' + comment.authorId + '" data-username="' + comment.authorUsername + '" data-discriminator="' + comment.authorDiscriminator + '" style="background: #dc2626; color: white; border: none; padding: 0.25rem 0.5rem; border-radius: 4px; cursor: pointer; font-size: 0.75rem;" title="Ban user (Admin only)">';
                    modalContent += '<i class="fas fa-ban"></i>';
                    modalContent += '</button>';
                    modalContent += '</div>';
                    modalContent += '<button class="ban-user-btn" data-user-id="' + comment.authorId + '" data-username="' + comment.authorUsername + '" data-discriminator="' + comment.authorDiscriminator + '" style="background: #dc2626; color: white; border: none; padding: 0.25rem 0.5rem; border-radius: 4px; cursor: pointer; font-size: 0.75rem;" title="Ban user (Admin only)">';
                    modalContent += '<i class="fas fa-ban"></i>';
                    modalContent += '</button>';
                    modalContent += '</div>';
                    modalContent += '</div>';
                    modalContent += '<p style="color: #cccccc; line-height: 1.6;">' + comment.content + '</p>';
                    modalContent += '</div>';
                }
            }
            modalContent += '</div>';
            modalContent += '</div>';
            modalContent += '</div>';

            modalBody.innerHTML = modalContent;

            // Add event listeners
            setupModalEventListeners(commandId);

            modal.classList.remove('hidden');
            modal.style.display = 'flex';
        }

        function closeCommandModal() {
            const modal = document.getElementById('command-details-modal');
            modal.classList.add('hidden');
            modal.style.display = 'none';
            document.getElementById('command-details-body').innerHTML = '';
        }

        function copyCommandFromModal(commandCode, commandName) {
            navigator.clipboard.writeText(commandCode).then(() => {
                showCopyModal(commandName);
            }).catch(err => {
                console.error('Failed to copy:', err);
                alert('Failed to copy command code. Please try again.');
            });
        }

        function setupModalEventListeners(commandId) {
            const modalBody = document.getElementById('command-details-body');

            // Copy button
            const copyBtn = modalBody.querySelector('#copy-command-btn');
            if (copyBtn) {
                copyBtn.addEventListener('click', () => {
                    const commandCode = copyBtn.getAttribute('data-command-code');
                    const command = allCommands.find(cmd => cmd.id === commandId);
                    copyCommandFromModal(commandCode, command.commandName);
                });
            }

            // Star rating
            const stars = modalBody.querySelectorAll('.star');
            let selectedRating = 0;

            stars.forEach(star => {
                star.style.opacity = '0.3';
                star.style.filter = 'grayscale(100%)';

                star.addEventListener('click', () => {
                    selectedRating = parseInt(star.dataset.rating);
                    updateStarDisplay(stars, selectedRating);
                });

                star.addEventListener('mouseover', () => {
                    const rating = parseInt(star.dataset.rating);
                    updateStarDisplay(stars, rating);
                });
            });

            const starRating = modalBody.querySelector('.star-rating');
            if (starRating) {
                starRating.addEventListener('mouseleave', () => {
                    updateStarDisplay(stars, selectedRating);
                });
            }

            function updateStarDisplay(stars, rating) {
                stars.forEach((star, index) => {
                    if (index < rating) {
                        star.style.opacity = '1';
                        star.style.filter = 'grayscale(0%)';
                    } else {
                        star.style.opacity = '0.3';
                        star.style.filter = 'grayscale(100%)';
                    }
                });
            }

            // Marketplace Discord login button
            const marketplaceLoginBtn = modalBody.querySelector('#marketplace-discord-login');
            if (marketplaceLoginBtn) {
                marketplaceLoginBtn.addEventListener('click', () => {
                    showLoginConfirmationModal();
                });
            }

            // Submit comment button
            const submitBtn = modalBody.querySelector('#submit-comment-btn');
            if (submitBtn) {
                submitBtn.addEventListener('click', async () => {
                    const commentText = document.getElementById('comment-text').value.trim();
                    if (!commentText) {
                        alert('Please enter a comment.');
                        return;
                    }

                    const sessionToken = localStorage.getItem('sessionToken');
                    if (!sessionToken) {
                        alert('Please login to post comments.');
                        return;
                    }

                    try {
                        const response = await fetch('/api/comments', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer ' + sessionToken
                            },
                            body: JSON.stringify({
                                submissionId: commandId,
                                content: commentText,
                                rating: selectedRating || null
                            })
                        });

                        const data = await response.json();
                        if (data.success) {
                            alert('Comment posted successfully!');
                            // Refresh the modal to show the new comment
                            viewCommandDetails(commandId);
                        } else {
                            throw new Error(data.error || 'Failed to post comment');
                        }
                    } catch (error) {
                        console.error('Error posting comment:', error);
                        alert('Failed to post comment: ' + error.message);
                    }
                });
            }

            // Delete comment buttons
            const deleteButtons = modalBody.querySelectorAll('.delete-comment-btn');
            deleteButtons.forEach(btn => {
                btn.addEventListener('click', async () => {
                    const commentId = btn.getAttribute('data-comment-id');

                    if (!confirm('Are you sure you want to delete this comment?')) {
                        return;
                    }

                    const sessionToken = localStorage.getItem('sessionToken');
                    if (!sessionToken) {
                        alert('Please login to delete comments.');
                        return;
                    }

                    try {
                        const response = await fetch('/api/delete-comment?id=' + commentId, {
                            method: 'DELETE',
                            headers: {
                                'Authorization': 'Bearer ' + sessionToken
                            }
                        });

                        const data = await response.json();
                        if (data.success) {
                            alert('Comment deleted successfully!');
                            // Refresh the modal to show updated comments
                            viewCommandDetails(commandId);
                        } else {
                            throw new Error(data.error || 'Failed to delete comment');
                        }
                    } catch (error) {
                        console.error('Error deleting comment:', error);
                        alert('Failed to delete comment: ' + error.message);
                    }
                });
            });

            // Ban user buttons
            const banButtons = modalBody.querySelectorAll('.ban-user-btn');
            banButtons.forEach(btn => {
                btn.addEventListener('click', async () => {
                    const userId = btn.getAttribute('data-user-id');
                    const username = btn.getAttribute('data-username');
                    const discriminator = btn.getAttribute('data-discriminator');

                    const reason = prompt('Enter ban reason (optional):');
                    if (reason === null) return; // User cancelled

                    if (!confirm('Are you sure you want to ban ' + username + '#' + discriminator + '?')) {
                        return;
                    }

                    const sessionToken = localStorage.getItem('sessionToken');
                    if (!sessionToken) {
                        alert('Please login to ban users.');
                        return;
                    }

                    try {
                        const response = await fetch('/api/ban-user', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer ' + sessionToken
                            },
                            body: JSON.stringify({
                                userId: userId,
                                username: username,
                                discriminator: discriminator,
                                reason: reason
                            })
                        });

                        const data = await response.json();
                        if (data.success) {
                            alert('User banned successfully!');
                            // Refresh the modal to show updated comments
                            viewCommandDetails(commandId);
                        } else {
                            throw new Error(data.error || 'Failed to ban user');
                        }
                    } catch (error) {
                        console.error('Error banning user:', error);
                        alert('Failed to ban user: ' + error.message);
                    }
                });
            });


        }



        // Show login confirmation modal
        function showLoginConfirmationModal() {
            const modal = document.getElementById('login-confirmation-modal');
            modal.classList.remove('hidden');
            modal.style.display = 'flex';

            // Add event listener to confirm button
            const confirmBtn = document.getElementById('confirm-discord-login');
            if (confirmBtn) {
                confirmBtn.onclick = async () => {
                    await handleMarketplaceDiscordLogin();
                };
            }
        }

        function closeLoginModal() {
            const modal = document.getElementById('login-confirmation-modal');
            modal.classList.add('hidden');
            modal.style.display = 'none';

            // Reset loading and error states
            const loadingDiv = document.getElementById('login-loading');
            const errorDiv = document.getElementById('login-error');
            if (loadingDiv) loadingDiv.classList.add('hidden');
            if (errorDiv) errorDiv.classList.add('hidden');
        }

        function showLoginSuccessModal() {
            const modal = document.getElementById('login-success-modal');
            modal.classList.remove('hidden');
            modal.style.display = 'flex';
        }

        function closeLoginSuccessModal() {
            const modal = document.getElementById('login-success-modal');
            modal.classList.add('hidden');
            modal.style.display = 'none';
        }

        // Marketplace Discord OAuth handling
        async function handleMarketplaceDiscordLogin() {
            const loadingDiv = document.getElementById('login-loading');
            const errorDiv = document.getElementById('login-error');
            const confirmBtn = document.getElementById('confirm-discord-login');

            try {
                // Show loading state
                if (loadingDiv) loadingDiv.classList.remove('hidden');
                if (errorDiv) errorDiv.classList.add('hidden');
                if (confirmBtn) confirmBtn.disabled = true;

                // Get Discord auth URL for marketplace
                const response = await fetch('/api/discord-auth?page=marketplace');
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || 'Failed to get Discord auth URL');
                }

                // Store state and current page for redirect back
                localStorage.setItem('oauthState', data.state);
                localStorage.setItem('oauthReturnPage', 'marketplace');

                // Redirect to Discord OAuth
                window.location.href = data.authUrl;

            } catch (error) {
                console.error('Discord auth error:', error);
                if (errorDiv) {
                    errorDiv.textContent = 'Failed to start Discord authentication: ' + error.message;
                    errorDiv.classList.remove('hidden');
                }
                if (loadingDiv) loadingDiv.classList.add('hidden');
                if (confirmBtn) confirmBtn.disabled = false;
            }
        }

        // Handle OAuth callback for marketplace
        async function handleMarketplaceOAuthCallback(code, state) {
            try {
                const response = await fetch('/api/discord-callback', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code, state, returnPage: 'marketplace' }),
                });

                const data = await response.json();

                if (data.success) {
                    // Store session token
                    localStorage.setItem('sessionToken', data.sessionToken);
                    localStorage.setItem('userData', JSON.stringify(data.user));

                    // Remove OAuth parameters from URL
                    const url = new URL(window.location);
                    url.searchParams.delete('code');
                    url.searchParams.delete('state');
                    window.history.replaceState({}, document.title, url.toString());

                    // Close login modal and show success modal
                    closeLoginModal();
                    showLoginSuccessModal();

                    // Auto-close success modal and reload after 3 seconds
                    setTimeout(() => {
                        closeLoginSuccessModal();
                        window.location.reload();
                    }, 3000);

                } else {
                    throw new Error(data.error || 'Failed to authenticate with Discord');
                }
            } catch (error) {
                console.error('OAuth callback error:', error);

                // Show error in login modal
                showLoginConfirmationModal();
                const errorDiv = document.getElementById('login-error');
                if (errorDiv) {
                    errorDiv.textContent = 'Failed to complete Discord authentication: ' + error.message;
                    errorDiv.classList.remove('hidden');
                }

                // Clean up URL
                const url = new URL(window.location);
                url.searchParams.delete('code');
                url.searchParams.delete('state');
                window.history.replaceState({}, document.title, url.toString());
            }
        }

        // Check for OAuth callback and load user info on marketplace page load
        document.addEventListener('DOMContentLoaded', () => {
            // Check for OAuth callback
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            const state = urlParams.get('state');
            const returnPage = localStorage.getItem('oauthReturnPage');

            if (code && state && returnPage === 'marketplace') {
                const storedState = localStorage.getItem('oauthState');

                // Clean up stored OAuth data
                localStorage.removeItem('oauthState');
                localStorage.removeItem('oauthReturnPage');

                if (state === storedState) {
                    handleMarketplaceOAuthCallback(code, state);
                } else {
                    // Show error in login modal
                    showLoginConfirmationModal();
                    const errorDiv = document.getElementById('login-error');
                    if (errorDiv) {
                        errorDiv.textContent = 'Invalid OAuth state. Please try logging in again.';
                        errorDiv.classList.remove('hidden');
                    }

                    // Clean up URL
                    const url = new URL(window.location);
                    url.searchParams.delete('code');
                    url.searchParams.delete('state');
                    window.history.replaceState({}, document.title, url.toString());
                }
            } else {
                // Load user info if logged in
                loadMarketplaceUserInfo();
            }
        });

        // Load user info for marketplace
        async function loadMarketplaceUserInfo() {
            const sessionToken = localStorage.getItem('sessionToken');
            if (!sessionToken) {
                // Ensure user info is hidden when no session
                const userInfo = document.getElementById('user-info');
                if (userInfo) userInfo.classList.add('hidden');
                return;
            }

            try {
                const response = await fetch('/api/get-user', {
                    headers: {
                        'Authorization': 'Bearer ' + sessionToken
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    displayMarketplaceUserInfo(data.user);
                } else {
                    // Invalid session, clear it and hide user info
                    localStorage.removeItem('sessionToken');
                    localStorage.removeItem('userData');
                    const userInfo = document.getElementById('user-info');
                    if (userInfo) userInfo.classList.add('hidden');
                }
            } catch (error) {
                console.error('Error loading user info:', error);
                // Hide user info on error
                const userInfo = document.getElementById('user-info');
                if (userInfo) userInfo.classList.add('hidden');
            }
        }

        function displayMarketplaceUserInfo(user) {
            const userInfo = document.getElementById('user-info');
            const userAvatar = document.getElementById('user-avatar');
            const userName = document.getElementById('user-name');
            const logoutBtn = document.getElementById('logout-btn');

            if (userInfo && userAvatar && userName) {
                userAvatar.src = user.avatar ?
                    'https://cdn.discordapp.com/avatars/' + user.id + '/' + user.avatar + '.png?size=64' :
                    'https://cdn.discordapp.com/embed/avatars/0.png';
                userName.textContent = user.username + '#' + user.discriminator;
                userInfo.classList.remove('hidden');

                if (logoutBtn) {
                    logoutBtn.addEventListener('click', () => {
                        localStorage.removeItem('sessionToken');
                        localStorage.removeItem('userData');
                        window.location.reload();
                    });
                }
            }
        }

        // Make functions globally accessible
        window.closeCopyModal = closeCopyModal;
        window.closeCommandModal = closeCommandModal;
        window.viewCommandDetails = viewCommandDetails;
        window.copyCommandFromModal = copyCommandFromModal;
        window.handleMarketplaceDiscordLogin = handleMarketplaceDiscordLogin;
        window.showLoginConfirmationModal = showLoginConfirmationModal;
        window.closeLoginModal = closeLoginModal;
        window.showLoginSuccessModal = showLoginSuccessModal;
        window.closeLoginSuccessModal = closeLoginSuccessModal;

        // Close modal when clicking outside
        document.addEventListener('DOMContentLoaded', () => {
            const copyModal = document.getElementById('copy-modal');
            if (copyModal) {
                copyModal.addEventListener('click', (e) => {
                    if (e.target === copyModal) {
                        closeCopyModal();
                    }
                });
            }
        });
    </script>

    <!-- Copy Success Modal -->
    <div id="copy-modal" class="modal hidden">
        <div class="modal-content" style="max-width: 400px; text-align: center;">
            <div class="modal-header" style="border-bottom: none; padding-bottom: 0;">
                <button class="close-btn" onclick="closeCopyModal()">&times;</button>
            </div>
            <div id="copy-modal-body">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>

    <!-- Command Details Modal -->
    <div id="command-details-modal" class="modal hidden">
        <div class="modal-content" style="max-width: 800px; max-height: 90vh; overflow-y: auto;">
            <div class="modal-header">
                <h3 class="modal-title">Command Details</h3>
                <button class="close-btn" onclick="closeCommandModal()">&times;</button>
            </div>
            <div id="command-details-body">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>

    <!-- Login Confirmation Modal -->
    <div id="login-confirmation-modal" class="modal hidden">
        <div class="modal-content" style="max-width: 500px; text-align: center;">
            <div class="modal-header" style="border-bottom: none; padding-bottom: 0;">
                <button class="close-btn" onclick="closeLoginModal()">&times;</button>
            </div>
            <div class="modal-body" style="padding: 2rem;">
                <div style="font-size: 3rem; margin-bottom: 1rem;">🔐</div>
                <h3 style="color: #ffffff; margin-bottom: 1rem;">Login Required</h3>
                <p style="color: #cccccc; margin-bottom: 2rem; line-height: 1.6;">
                    You need to authenticate with Discord to post comments and reviews.
                    This helps us maintain a safe and trusted community.
                </p>
                <div style="display: flex; gap: 1rem; justify-content: center;">
                    <button id="confirm-discord-login" style="background: #5865f2; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; cursor: pointer; font-weight: 600; display: flex; align-items: center; gap: 0.5rem;">
                        <i class="fab fa-discord"></i>
                        Continue with Discord
                    </button>
                    <button onclick="closeLoginModal()" style="background: #6b7280; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; cursor: pointer; font-weight: 600;">
                        Cancel
                    </button>
                </div>
                <div id="login-loading" class="loading hidden" style="margin-top: 1.5rem;">
                    <div style="color: #cccccc;">Connecting to Discord...</div>
                </div>
                <div id="login-error" class="alert alert-error hidden" style="margin-top: 1.5rem; text-align: left;"></div>
            </div>
        </div>
    </div>

    <!-- Login Success Modal -->
    <div id="login-success-modal" class="modal hidden">
        <div class="modal-content" style="max-width: 400px; text-align: center;">
            <div class="modal-header" style="border-bottom: none; padding-bottom: 0;">
                <button class="close-btn" onclick="closeLoginSuccessModal()">&times;</button>
            </div>
            <div class="modal-body" style="padding: 2rem;">
                <div style="font-size: 3rem; margin-bottom: 1rem;">✅</div>
                <h3 style="color: #ffffff; margin-bottom: 1rem;">Welcome!</h3>
                <p style="color: #cccccc; margin-bottom: 2rem; line-height: 1.6;">
                    Successfully logged in with Discord. You can now post comments and reviews!
                </p>
                <button onclick="closeLoginSuccessModal()" style="background: #22c55e; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; cursor: pointer; font-weight: 600;">
                    Continue
                </button>
            </div>
        </div>
    </div>
</body>
</html>`,
    '/admin': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Code Hub</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            line-height: 1.6;
        }

        /* Header */
        .header {
            background: rgba(10, 10, 10, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid #1a1a1a;
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .nav {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 2rem;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: #ffffff;
            text-decoration: none;
        }

        .logo-icon {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, #ef4444, #dc2626);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            color: #fff;
        }

        .admin-badge {
            background: #ef4444;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 0.5rem;
        }

        .user-nav {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 0.75rem;
        }

        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 8px;
        }

        /* Main Content */
        .main {
            max-width: 1200px;
            margin: 0 auto;
            padding: 3rem 2rem;
        }

        .page-header {
            margin-bottom: 3rem;
        }

        .page-title {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #ef4444, #dc2626);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .page-subtitle {
            font-size: 1.125rem;
            color: #cccccc;
        }

        /* Access Denied */
        .access-denied {
            text-align: center;
            padding: 4rem 2rem;
        }

        .access-denied-icon {
            font-size: 4rem;
            color: #ef4444;
            margin-bottom: 1rem;
        }

        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }

        .stat-card {
            background: linear-gradient(135deg, #1a1a1a, #0f0f0f);
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }

        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 0.5rem;
        }

        .stat-label {
            color: #888888;
            font-size: 0.875rem;
        }

        /* Filters */
        .filters {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 0.75rem 1.5rem;
            background: transparent;
            color: #cccccc;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        .filter-btn:hover, .filter-btn.active {
            background: #ffffff;
            color: #000000;
            border-color: #ffffff;
        }

        /* Submissions Table */
        .submissions-container {
            background: linear-gradient(135deg, #1a1a1a, #0f0f0f);
            border: 1px solid #2a2a2a;
            border-radius: 16px;
            overflow: hidden;
        }

        .submissions-table {
            width: 100%;
            border-collapse: collapse;
        }

        .submissions-table th {
            background: #111111;
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            color: #ffffff;
            border-bottom: 1px solid #2a2a2a;
        }

        .submissions-table td {
            padding: 1rem;
            border-bottom: 1px solid #1a1a1a;
            vertical-align: top;
        }

        .submissions-table tr:hover {
            background: rgba(255, 255, 255, 0.02);
        }

        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-pending {
            background: rgba(251, 191, 36, 0.2);
            color: #fbbf24;
            border: 1px solid rgba(251, 191, 36, 0.3);
        }

        .status-approved {
            background: rgba(34, 197, 94, 0.2);
            color: #22c55e;
            border: 1px solid rgba(34, 197, 94, 0.3);
        }

        .status-rejected {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .action-btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            margin-right: 0.5rem;
            transition: all 0.3s ease;
        }

        .btn-approve {
            background: #22c55e;
            color: white;
        }

        .btn-approve:hover {
            background: #16a34a;
        }

        .btn-reject {
            background: #ef4444;
            color: white;
        }

        .btn-reject:hover {
            background: #dc2626;
        }

        .btn-view {
            background: #3b82f6;
            color: white;
        }

        .btn-view:hover {
            background: #2563eb;
        }

        .command-preview {
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .user-info-cell {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .user-avatar-small {
            width: 24px;
            height: 24px;
            border-radius: 4px;
        }

        /* Loading */
        .loading {
            text-align: center;
            padding: 4rem 2rem;
        }

        .spinner {
            display: inline-block;
            width: 40px;
            height: 40px;
            border: 3px solid #333333;
            border-top: 3px solid #ffffff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Modal */
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }

        .modal.hidden {
            display: none !important;
        }

        .modal-content {
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 16px;
            padding: 2rem;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .modal-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: #ffffff;
        }

        .close-btn {
            background: none;
            border: none;
            color: #888888;
            font-size: 1.5rem;
            cursor: pointer;
        }

        .close-btn:hover {
            color: #ffffff;
        }

        .command-details {
            margin-bottom: 1rem;
        }

        .command-details h4 {
            color: #ffffff;
            margin-bottom: 0.5rem;
        }

        .command-details p {
            color: #cccccc;
            margin-bottom: 1rem;
        }

        .command-code {
            background: #111111;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            color: #ffffff;
            word-break: break-all;
            max-height: 200px;
            overflow-y: auto;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .nav {
                padding: 0 1rem;
            }

            .main {
                padding: 2rem 1rem;
            }

            .submissions-table {
                font-size: 0.875rem;
            }

            .submissions-table th,
            .submissions-table td {
                padding: 0.75rem 0.5rem;
            }

            .filters {
                flex-direction: column;
            }

            .filter-btn {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <nav class="nav">
            <a href="/" class="logo">
                <div class="logo-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                Admin Dashboard
                <span class="admin-badge">ADMIN</span>
            </a>
            <div class="user-nav">
                <div id="user-info" class="user-info hidden">
                    <img id="user-avatar" class="user-avatar" alt="User Avatar">
                    <div>
                        <div id="user-name" style="font-weight: 600; color: #ffffff;"></div>
                        <div style="font-size: 0.75rem; color: #888888;">Administrator</div>
                    </div>
                    <button id="logout-btn" class="action-btn btn-reject">
                        <i class="fas fa-sign-out-alt"></i>
                        Logout
                    </button>
                </div>
            </div>
        </nav>
    </header>

    <!-- Main Content -->
    <main class="main">
        <!-- Access Check -->
        <div id="access-check" class="loading">
            <div class="spinner"></div>
            <p style="margin-top: 1rem; color: #cccccc;">Checking access permissions...</p>
        </div>

        <!-- Access Denied -->
        <div id="access-denied" class="access-denied hidden">
            <div class="access-denied-icon">
                <i class="fas fa-ban"></i>
            </div>
            <h2 style="color: #ef4444; margin-bottom: 1rem;">Access Denied</h2>
            <p style="color: #cccccc; margin-bottom: 2rem;">You don't have permission to access the admin dashboard.</p>
            <a href="/" class="action-btn btn-view">
                <i class="fas fa-home"></i>
                Back to Homepage
            </a>
        </div>

        <!-- Admin Dashboard -->
        <div id="admin-dashboard" class="hidden">
            <div class="page-header">
                <h1 class="page-title">Admin Dashboard</h1>
                <p class="page-subtitle">Manage command submissions and moderate the marketplace</p>
            </div>

            <!-- Stats -->
            <div id="stats-grid" class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" id="stat-pending">-</div>
                    <div class="stat-label">Pending Review</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="stat-approved">-</div>
                    <div class="stat-label">Approved</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="stat-rejected">-</div>
                    <div class="stat-label">Rejected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="stat-total">-</div>
                    <div class="stat-label">Total Submissions</div>
                </div>
            </div>

            <!-- Filters -->
            <div class="filters">
                <button class="filter-btn active" data-status="all">All Submissions</button>
                <button class="filter-btn" data-status="pending">Pending Review</button>
                <button class="filter-btn" data-status="approved">Approved</button>
                <button class="filter-btn" data-status="rejected">Rejected</button>
                <button class="filter-btn" id="banned-users-btn" style="background: #ef4444; color: white; border-color: #ef4444;">Banned Users</button>
            </div>

            <!-- Submissions Table -->
            <div class="submissions-container">
                <table class="submissions-table">
                    <thead>
                        <tr>
                            <th>Command</th>
                            <th>Submitted By</th>
                            <th>Status</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="submissions-tbody">
                        <tr>
                            <td colspan="5" style="text-align: center; padding: 2rem; color: #888888;">
                                Loading submissions...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <!-- Command Details Modal -->
    <div id="command-modal" class="modal hidden">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Command Details</h3>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div id="modal-body">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>

    <!-- Status Update Modal -->
    <div id="status-modal" class="modal hidden">
        <div class="modal-content" style="max-width: 400px; text-align: center;">
            <div class="modal-header" style="border-bottom: none; padding-bottom: 0;">
                <button class="close-btn" onclick="closeStatusModal()">&times;</button>
            </div>
            <div id="status-modal-body">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>

    <script>
        let currentUser = null;
        let allSubmissions = [];
        let currentFilter = 'all';

        // DOM elements
        const accessCheck = document.getElementById('access-check');
        const accessDenied = document.getElementById('access-denied');
        const adminDashboard = document.getElementById('admin-dashboard');
        const userInfo = document.getElementById('user-info');
        const userAvatar = document.getElementById('user-avatar');
        const userName = document.getElementById('user-name');
        const logoutBtn = document.getElementById('logout-btn');
        const submissionsTbody = document.getElementById('submissions-tbody');
        const commandModal = document.getElementById('command-modal');
        const statusModal = document.getElementById('status-modal');

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            console.log('DOM loaded, initializing admin dashboard');

            // Force initial state with style attribute to override any CSS issues
            accessCheck.style.display = 'block';
            accessDenied.style.display = 'none';
            adminDashboard.style.display = 'none';
            userInfo.style.display = 'none';
            commandModal.style.display = 'none';
            statusModal.style.display = 'none';

            console.log('Initial state forced with inline styles');

            // Small delay to ensure DOM is fully ready
            setTimeout(() => {
                checkAccess();
            }, 100);
        });

        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentFilter = btn.dataset.status;
                if (currentFilter) {
                    renderSubmissions();
                }
            });
        });

        // Banned users button
        document.getElementById('banned-users-btn').addEventListener('click', () => {
            // Remove active class from all buttons
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            // Add active class to banned users button
            document.getElementById('banned-users-btn').classList.add('active');

            // Update page title
            document.querySelector('.page-title').textContent = 'Banned Users';
            document.querySelector('.page-subtitle').textContent = 'Manage banned users and their access to the platform.';

            loadBannedUsers();
        });

        // Logout
        logoutBtn.addEventListener('click', () => {
            localStorage.removeItem('sessionToken');
            window.location.href = '/';
        });

        async function checkAccess() {
            const sessionToken = localStorage.getItem('sessionToken');

            if (!sessionToken) {
                // Redirect to submit page for OAuth
                window.location.href = '/submit.html?redirect=admin';
                return;
            }

            try {
                const response = await fetch('/api/get-user', {
                    headers: { 'Authorization': 'Bearer ' + sessionToken }
                });

                if (!response.ok) {
                    localStorage.removeItem('sessionToken');
                    window.location.href = '/submit.html?redirect=admin';
                    return;
                }

                const data = await response.json();
                currentUser = data.user;

                // Check if user is admin
                const adminResponse = await fetch('/api/check-admin', {
                    headers: { 'Authorization': 'Bearer ' + sessionToken }
                });

                if (adminResponse.ok) {
                    const adminData = await adminResponse.json();
                    console.log('Admin check response:', adminData);
                    if (adminData.isAdmin) {
                        console.log('User is admin, showing dashboard');
                        showAdminDashboard();
                    } else {
                        console.log('User is not admin, showing access denied');
                        showAccessDenied();
                    }
                } else {
                    console.log('Admin check failed, showing access denied');
                    showAccessDenied();
                }
            } catch (error) {
                console.error('Access check error:', error);
                showAccessDenied();
            }
        }

        function showAdminDashboard() {
            console.log('showAdminDashboard called');

            // Use inline styles to force visibility
            accessCheck.style.display = 'none';
            accessDenied.style.display = 'none';
            adminDashboard.style.display = 'block';
            userInfo.style.display = 'flex';

            console.log('Admin dashboard shown with inline styles');

            // Update user info
            userName.textContent = \`\${currentUser.username}#\${currentUser.discriminator}\`;
            if (currentUser.avatar) {
                userAvatar.src = \`https://cdn.discordapp.com/avatars/\${currentUser.id}/\${currentUser.avatar}.png\`;
            } else {
                userAvatar.src = \`https://cdn.discordapp.com/embed/avatars/\${currentUser.discriminator % 5}.png\`;
            }

            loadSubmissions();
        }

        // Load banned users
        async function loadBannedUsers() {
            try {
                const sessionToken = localStorage.getItem('sessionToken');
                if (!sessionToken) {
                    window.location.href = '/submit';
                    return;
                }

                const response = await fetch('/api/banned-users', {
                    headers: {
                        'Authorization': 'Bearer ' + sessionToken
                    }
                });

                const data = await response.json();
                if (data.success) {
                    displayBannedUsers(data.bannedUsers);
                } else {
                    throw new Error(data.error || 'Failed to load banned users');
                }
            } catch (error) {
                console.error('Error loading banned users:', error);
                document.getElementById('submissions-container').innerHTML =
                    '<div class="loading"><p>Error loading banned users: ' + error.message + '</p></div>';
            }
        }

        function displayBannedUsers(bannedUsers) {
            const container = document.getElementById('submissions-container');

            if (bannedUsers.length === 0) {
                container.innerHTML = '<div class="loading"><p>No banned users found.</p></div>';
                return;
            }

            let html = '<div class="submissions-container">';
            html += '<table class="submissions-table">';
            html += '<thead>';
            html += '<tr>';
            html += '<th>User</th>';
            html += '<th>Banned At</th>';
            html += '<th>Reason</th>';
            html += '<th>Actions</th>';
            html += '</tr>';
            html += '</thead>';
            html += '<tbody>';

            bannedUsers.forEach(user => {
                html += '<tr>';
                html += '<td>' + user.username + '#' + user.discriminator + '</td>';
                html += '<td>' + new Date(user.banned_at).toLocaleDateString() + '</td>';
                html += '<td>' + (user.reason || 'No reason provided') + '</td>';
                html += '<td>';
                html += '<button class="action-btn btn-reject" onclick="alert(&quot;Unban functionality coming soon!&quot;)">Unban</button>';
                html += '</td>';
                html += '</tr>';
            });

            html += '</tbody>';
            html += '</table>';
            html += '</div>';

            container.innerHTML = html;
        }

        function showAccessDenied() {
            console.log('showAccessDenied called');

            // Use inline styles to force visibility
            accessCheck.style.display = 'none';
            adminDashboard.style.display = 'none';
            userInfo.style.display = 'none';
            accessDenied.style.display = 'block';

            console.log('Access denied shown with inline styles');
        }

        async function loadSubmissions() {
            try {
                const response = await fetch('/api/get-submissions?status=all&stats=true');
                const data = await response.json();

                if (data.success) {
                    allSubmissions = data.submissions;
                    updateStats(data.stats);
                    renderSubmissions();
                }
            } catch (error) {
                console.error('Error loading submissions:', error);
                submissionsTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem; color: #ef4444;">Error loading submissions</td></tr>';
            }
        }

        function updateStats(stats) {
            document.getElementById('stat-pending').textContent = stats.pending || 0;
            document.getElementById('stat-approved').textContent = stats.approved || 0;
            document.getElementById('stat-rejected').textContent = stats.rejected || 0;
            document.getElementById('stat-total').textContent = Object.values(stats).reduce((a, b) => a + b, 0);
        }

        function renderSubmissions() {
            const filtered = currentFilter === 'all'
                ? allSubmissions
                : allSubmissions.filter(sub => sub.status === currentFilter);

            if (filtered.length === 0) {
                submissionsTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem; color: #888888;">No submissions found</td></tr>';
                return;
            }

            submissionsTbody.innerHTML = filtered.map(submission => \`
                <tr>
                    <td>
                        <div>
                            <div style="font-weight: 600; color: #ffffff; margin-bottom: 0.25rem;">\${submission.commandName}</div>
                            <div class="command-preview" style="color: #888888; font-size: 0.875rem;">\${submission.commandDescription}</div>
                        </div>
                    </td>
                    <td>
                        <div class="user-info-cell">
                            <div>
                                <div style="font-weight: 500; color: #ffffff;">\${submission.submittedBy.username}</div>
                                <div style="font-size: 0.75rem; color: #888888;">#\${submission.submittedBy.discriminator}</div>
                            </div>
                        </div>
                    </td>
                    <td>
                        <span class="status-badge status-\${submission.status}">\${submission.status}</span>
                    </td>
                    <td style="color: #888888; font-size: 0.875rem;">
                        \${new Date(submission.submittedAt).toLocaleDateString()}
                    </td>
                    <td>
                        <button class="action-btn btn-view" onclick="viewCommand('\${submission.id}')">
                            <i class="fas fa-eye"></i>
                            View
                        </button>
                        \${submission.status === 'pending' ? \`
                            <button class="action-btn btn-approve" onclick="updateStatus('\${submission.id}', 'approved')">
                                <i class="fas fa-check"></i>
                                Approve
                            </button>
                            <button class="action-btn btn-reject" onclick="updateStatus('\${submission.id}', 'rejected')">
                                <i class="fas fa-times"></i>
                                Reject
                            </button>
                        \` : ''}
                        <button class="action-btn btn-delete" onclick="deleteSubmission('\${submission.id}', '\${submission.commandName}')" style="background: #dc2626; border-color: #dc2626;">
                            <i class="fas fa-trash"></i>
                            Delete
                        </button>
                    </td>
                </tr>
            \`).join('');
        }

        function viewCommand(submissionId) {
            console.log('viewCommand called with ID:', submissionId);
            console.log('allSubmissions:', allSubmissions);

            const submission = allSubmissions.find(s => s.id === submissionId);
            console.log('Found submission:', submission);

            if (!submission) {
                console.error('No submission found with ID:', submissionId);
                return;
            }

            const modalBody = document.getElementById('modal-body');
            console.log('Modal body element:', modalBody);

            if (!modalBody) {
                console.error('Modal body element not found');
                return;
            }

            modalBody.innerHTML = \`
                <div class="command-details">
                    <h4>Command Name</h4>
                    <p>\${submission.commandName}</p>

                    <h4>Description</h4>
                    <p>\${submission.commandDescription}</p>

                    <h4>Submitted By</h4>
                    <p>\${submission.submittedBy.username}#\${submission.submittedBy.discriminator}</p>

                    <h4>Submission Date</h4>
                    <p>\${new Date(submission.submittedAt).toLocaleString()}</p>

                    <h4>Status</h4>
                    <p><span class="status-badge status-\${submission.status}">\${submission.status}</span></p>

                    <h4>Command Code</h4>
                    <div class="command-code">\${submission.commandCode}</div>

                    \${submission.images && submission.images.length > 0 ? \`
                        <h4>Images</h4>
                        <p>\${submission.images.length} image(s) uploaded</p>
                    \` : ''}
                </div>
            \`;

            console.log('commandModal element:', commandModal);
            console.log('Modal classes before:', commandModal.className);

            // Remove hidden class and set display
            commandModal.classList.remove('hidden');
            commandModal.style.display = 'flex';

            console.log('Modal classes after:', commandModal.className);
            console.log('Modal display style after setting:', commandModal.style.display);
        }

        function closeModal() {
            commandModal.classList.add('hidden');
            commandModal.style.display = 'none';
            // Clear modal content
            document.getElementById('modal-body').innerHTML = '';
        }

        function showStatusModal(status, commandName) {
            const statusModalBody = document.getElementById('status-modal-body');

            const isApproved = status === 'approved';
            const icon = isApproved ? 'fas fa-check-circle' : 'fas fa-times-circle';
            const iconColor = isApproved ? '#22c55e' : '#ef4444';
            const title = isApproved ? 'Command Approved!' : 'Command Rejected';
            const message = isApproved
                ? '"' + commandName + '" has been approved and is now live in the marketplace.'
                : '"' + commandName + '" has been rejected and will not appear in the marketplace.';

            statusModalBody.innerHTML = '<div style="padding: 2rem 1rem;">' +
                '<div style="font-size: 4rem; color: ' + iconColor + '; margin-bottom: 1rem;">' +
                    '<i class="' + icon + '"></i>' +
                '</div>' +
                '<h3 style="color: #ffffff; margin-bottom: 1rem; font-size: 1.5rem;">' + title + '</h3>' +
                '<p style="color: #cccccc; margin-bottom: 2rem; line-height: 1.6;">' + message + '</p>' +
                '<button onclick="closeStatusModal()" class="action-btn" style="background: ' + iconColor + '; color: white; padding: 0.75rem 2rem; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;">' +
                    '<i class="fas fa-check"></i> Got it' +
                '</button>' +
            '</div>';

            statusModal.classList.remove('hidden');
            statusModal.style.display = 'flex';
        }

        function closeStatusModal() {
            statusModal.classList.add('hidden');
            statusModal.style.display = 'none';
            document.getElementById('status-modal-body').innerHTML = '';
        }

        // Make functions globally accessible
        window.closeModal = closeModal;
        window.closeStatusModal = closeStatusModal;
        window.viewCommand = viewCommand;
        window.updateStatus = updateStatus;
        window.deleteSubmission = deleteSubmission;

        async function updateStatus(submissionId, newStatus) {
            try {
                const sessionToken = localStorage.getItem('sessionToken');
                const response = await fetch('/api/update-submission-status', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + sessionToken
                    },
                    body: JSON.stringify({
                        submissionId: submissionId,
                        status: newStatus
                    })
                });

                if (response.ok) {
                    // Update local data
                    const submission = allSubmissions.find(s => s.id === submissionId);
                    if (submission) {
                        submission.status = newStatus;

                        // Show custom status modal
                        showStatusModal(newStatus, submission.commandName);
                    }

                    // Refresh display
                    loadSubmissions();
                } else {
                    throw new Error('Failed to update status');
                }
            } catch (error) {
                console.error('Error updating status:', error);
                alert('Failed to update command status. Please try again.');
            }
        }

        async function deleteSubmission(submissionId, commandName) {
            if (!confirm(\`Are you sure you want to permanently delete "\${commandName}"? This action cannot be undone.\`)) {
                return;
            }

            try {
                const sessionToken = localStorage.getItem('sessionToken');
                const response = await fetch(\`/api/delete-submission?id=\${submissionId}\`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': 'Bearer ' + sessionToken
                    }
                });

                if (response.ok) {
                    // Remove from local data
                    const index = allSubmissions.findIndex(s => s.id === submissionId);
                    if (index !== -1) {
                        allSubmissions.splice(index, 1);
                    }

                    // Show success message
                    alert(\`"\${commandName}" has been permanently deleted.\`);

                    // Refresh display
                    loadSubmissions();
                } else {
                    const errorData = await response.json();
                    throw new Error(errorData.error || 'Failed to delete submission');
                }
            } catch (error) {
                console.error('Error deleting submission:', error);
                alert('Failed to delete command. Please try again.');
            }
        }

        // Close modals when clicking outside
        commandModal.addEventListener('click', (e) => {
            if (e.target === commandModal) {
                closeModal();
            }
        });

        statusModal.addEventListener('click', (e) => {
            if (e.target === statusModal) {
                closeStatusModal();
            }
        });
    </script>
</body>
</html>`,
    '/docs': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Documentation - Code Hub</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            line-height: 1.6;
        }

        /* Header */
        .header {
            background: rgba(10, 10, 10, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid #1a1a1a;
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .nav {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 2rem;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: #ffffff;
            text-decoration: none;
        }

        .logo-icon {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, #ffffff, #cccccc);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            color: #000;
        }

        .nav-links {
            display: flex;
            gap: 2rem;
            list-style: none;
        }

        .nav-links a {
            color: #cccccc;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }

        .nav-links a:hover, .nav-links a.active {
            color: #ffffff;
        }

        .user-nav {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-info-card {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 0.5rem 1rem;
        }

        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            border: 2px solid rgba(255, 255, 255, 0.2);
        }

        .user-details {
            display: flex;
            flex-direction: column;
            gap: 0.125rem;
        }

        .user-name {
            font-size: 0.875rem;
            font-weight: 600;
            color: #ffffff;
        }

        .user-status {
            font-size: 0.75rem;
            color: #888888;
        }

        .logout-btn {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #ef4444;
            padding: 0.375rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.375rem;
        }

        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.2);
            border-color: rgba(239, 68, 68, 0.5);
        }

        /* Layout */
        .docs-layout {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 250px 1fr;
            gap: 3rem;
            padding: 3rem 2rem;
        }

        /* Sidebar */
        .sidebar {
            position: sticky;
            top: 120px;
            height: fit-content;
        }

        .sidebar-section {
            margin-bottom: 2rem;
        }

        .sidebar-title {
            font-size: 0.875rem;
            font-weight: 600;
            color: #888888;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 1rem;
        }

        .sidebar-nav {
            list-style: none;
        }

        .sidebar-nav li {
            margin-bottom: 0.5rem;
        }

        .sidebar-nav a {
            color: #cccccc;
            text-decoration: none;
            padding: 0.5rem 0;
            display: block;
            transition: color 0.3s ease;
        }

        .sidebar-nav a:hover, .sidebar-nav a.active {
            color: #ffffff;
        }

        /* Content */
        .content {
            min-width: 0;
        }

        .content h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #ffffff, #cccccc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .content h2 {
            font-size: 1.75rem;
            font-weight: 600;
            margin: 2rem 0 1rem;
            color: #ffffff;
            border-bottom: 1px solid #2a2a2a;
            padding-bottom: 0.5rem;
        }

        .content h3 {
            font-size: 1.25rem;
            font-weight: 600;
            margin: 1.5rem 0 0.75rem;
            color: #ffffff;
        }

        .content p {
            color: #cccccc;
            margin-bottom: 1rem;
        }

        .content ul, .content ol {
            color: #cccccc;
            margin-bottom: 1rem;
            padding-left: 1.5rem;
        }

        .content li {
            margin-bottom: 0.5rem;
        }

        /* Code blocks */
        .code-block {
            background: #111111;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1.5rem 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            position: relative;
        }

        .code-block pre {
            margin: 0;
            color: #ffffff;
        }

        .copy-code-btn {
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            color: #ffffff;
            padding: 0.5rem;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .copy-code-btn:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        /* Inline code */
        code {
            background: rgba(255, 255, 255, 0.1);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            color: #ffffff;
        }

        /* Callouts */
        .callout {
            background: linear-gradient(135deg, #1a1a1a, #0f0f0f);
            border: 1px solid #2a2a2a;
            border-left: 4px solid #ffffff;
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1.5rem 0;
        }

        .callout.info {
            border-left-color: #3b82f6;
        }

        .callout.warning {
            border-left-color: #f59e0b;
        }

        .callout.success {
            border-left-color: #10b981;
        }

        .callout-title {
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #ffffff;
        }

        /* Steps */
        .steps {
            counter-reset: step;
        }

        .step {
            counter-increment: step;
            background: linear-gradient(135deg, #1a1a1a, #0f0f0f);
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
            position: relative;
            padding-left: 4rem;
        }

        .step::before {
            content: counter(step);
            position: absolute;
            left: 1.5rem;
            top: 1.5rem;
            width: 2rem;
            height: 2rem;
            background: #ffffff;
            color: #000000;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.875rem;
        }

        .step h4 {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #ffffff;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .nav {
                padding: 0 1rem;
            }

            .nav-links {
                display: none;
            }

            .docs-layout {
                grid-template-columns: 1fr;
                padding: 2rem 1rem;
                gap: 2rem;
            }

            .sidebar {
                position: static;
                order: 2;
            }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <nav class="nav">
            <a href="/" class="logo">
                <div class="logo-icon">
                    <i class="fas fa-code"></i>
                </div>
                Code Hub
            </a>
            <ul class="nav-links">
                <li><a href="/">Features</a></li>
                <li><a href="/marketplace">Marketplace</a></li>
                <li><a href="/submit">Submit</a></li>
                <li><a href="/docs" class="active">Documentation</a></li>
            </ul>
            <div class="user-nav">
                <div id="user-info" class="user-info-card hidden">
                    <img id="user-avatar" class="user-avatar" alt="User Avatar">
                    <div class="user-details">
                        <div id="user-name" class="user-name"></div>
                        <div class="user-status">Authenticated</div>
                    </div>
                    <button id="logout-btn" class="logout-btn">
                        <i class="fas fa-sign-out-alt"></i>
                        Logout
                    </button>
                </div>
            </div>
        </nav>
    </header>

    <!-- Main Layout -->
    <div class="docs-layout">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="sidebar-section">
                <div class="sidebar-title">Getting Started</div>
                <ul class="sidebar-nav">
                    <li><a href="#introduction" class="active">Introduction</a></li>
                    <li><a href="#how-it-works">How It Works</a></li>
                    <li><a href="#quick-start">Quick Start</a></li>
                </ul>
            </div>
            <div class="sidebar-section">
                <div class="sidebar-title">Using Commands</div>
                <ul class="sidebar-nav">
                    <li><a href="#finding-commands">Finding Commands</a></li>
                    <li><a href="#importing-commands">Importing Commands</a></li>
                    <li><a href="#customizing">Customizing</a></li>
                </ul>
            </div>
            <div class="sidebar-section">
                <div class="sidebar-title">Contributing</div>
                <ul class="sidebar-nav">
                    <li><a href="#submitting-commands">Submitting Commands</a></li>
                    <li><a href="#best-practices">Best Practices</a></li>
                    <li><a href="#guidelines">Guidelines</a></li>
                </ul>
            </div>
        </aside>

        <!-- Content -->
        <main class="content">
            <section id="introduction">
                <h1>Code Hub Documentation</h1>
                <p>Welcome to Code Hub, the premier marketplace for BotGhost command codes. This documentation will help you discover, import, and share BotGhost commands with the community.</p>

                <div class="callout info">
                    <div class="callout-title">What is Code Hub?</div>
                    <p>Code Hub is a community-driven platform where BotGhost users can share and discover command codes. All commands are created using BotGhost's visual editor and can be imported directly into your bot.</p>
                </div>
            </section>

            <section id="how-it-works">
                <h2>How It Works</h2>
                <p>Code Hub simplifies the process of sharing BotGhost commands. Here's how the platform works:</p>

                <div class="steps">
                    <div class="step">
                        <h4>Create in BotGhost</h4>
                        <p>Build your command using BotGhost's visual editor. Test it thoroughly to ensure it works as expected.</p>
                    </div>
                    <div class="step">
                        <h4>Export Command Code</h4>
                        <p>Use BotGhost's export feature to generate a command code that starts with <code>CMD_</code>.</p>
                    </div>
                    <div class="step">
                        <h4>Submit to Code Hub</h4>
                        <p>Share your command code on Code Hub with a description and screenshots.</p>
                    </div>
                    <div class="step">
                        <h4>Community Discovery</h4>
                        <p>Other users can find your command, copy the code, and import it into their own BotGhost bots.</p>
                    </div>
                </div>
            </section>

            <section id="quick-start">
                <h2>Quick Start</h2>
                <p>Get started with Code Hub in just a few minutes:</p>

                <h3>For Command Users</h3>
                <ol>
                    <li>Browse the <a href="/marketplace" style="color: #ffffff;">marketplace</a> to find commands</li>
                    <li>Click "Copy Code" on any command you like</li>
                    <li>Go to your BotGhost dashboard</li>
                    <li>Use the import feature and paste the command code</li>
                    <li>Customize the command as needed</li>
                </ol>

                <h3>For Command Creators</h3>
                <ol>
                    <li>Create and test your command in BotGhost</li>
                    <li>Export the command to get the command code</li>
                    <li>Visit the <a href="/submit.html" style="color: #ffffff;">submit page</a></li>
                    <li>Authenticate with Discord</li>
                    <li>Fill out the submission form with your command details</li>
                </ol>
            </section>

            <section id="finding-commands">
                <h2>Finding Commands</h2>
                <p>The marketplace offers several ways to discover commands:</p>

                <h3>Browse by Category</h3>
                <p>Commands are automatically categorized based on their functionality:</p>
                <ul>
                    <li><strong>Moderation:</strong> Ban, kick, warn, and other moderation tools</li>
                    <li><strong>Fun:</strong> Games, jokes, memes, and entertainment</li>
                    <li><strong>Utility:</strong> Information, help, and useful tools</li>
                    <li><strong>Economy:</strong> Virtual currency and shop systems</li>
                    <li><strong>Music:</strong> Music playback and audio commands</li>
                    <li><strong>Games:</strong> Interactive games and activities</li>
                </ul>

                <h3>Search Commands</h3>
                <p>Use the search bar to find specific commands by name or description. The search is real-time and will filter results as you type.</p>

                <div class="callout info">
                    <div class="callout-title">Pro Tip</div>
                    <p>Try searching for specific keywords like "ticket", "welcome", or "level" to find commands related to those features.</p>
                </div>
            </section>

            <section id="importing-commands">
                <h2>Importing Commands</h2>
                <p>Once you've found a command you want to use, importing it into your BotGhost bot is simple:</p>

                <div class="code-block">
                    <button class="copy-code-btn" onclick="copyCode(this)">
                        <i class="fas fa-copy"></i>
                    </button>
                    <pre>1. Copy the command code from Code Hub
2. Open your BotGhost dashboard
3. Navigate to Commands → Import
4. Paste the command code
5. Click "Import Command"
6. Customize settings as needed</pre>
                </div>

                <div class="callout warning">
                    <div class="callout-title">Important</div>
                    <p>Always review imported commands before enabling them. Make sure they fit your server's rules and requirements.</p>
                </div>
            </section>

            <section id="customizing">
                <h2>Customizing Commands</h2>
                <p>After importing a command, you can customize it to fit your server:</p>

                <h3>Common Customizations</h3>
                <ul>
                    <li><strong>Permissions:</strong> Set who can use the command</li>
                    <li><strong>Channels:</strong> Restrict commands to specific channels</li>
                    <li><strong>Messages:</strong> Customize response messages and embeds</li>
                    <li><strong>Variables:</strong> Adjust settings and parameters</li>
                </ul>

                <h3>Testing Commands</h3>
                <p>Before making commands live, test them in a private channel or test server to ensure they work correctly.</p>
            </section>

            <section id="submitting-commands">
                <h2>Submitting Commands</h2>
                <p>Share your creations with the community by submitting commands to Code Hub:</p>

                <h3>Requirements</h3>
                <ul>
                    <li>Command must be created in BotGhost</li>
                    <li>Command code must start with <code>CMD_</code></li>
                    <li>Provide a clear name and description</li>
                    <li>Include screenshots if helpful</li>
                </ul>

                <h3>Submission Process</h3>
                <div class="steps">
                    <div class="step">
                        <h4>Authenticate</h4>
                        <p>Log in with your Discord account to verify your identity.</p>
                    </div>
                    <div class="step">
                        <h4>Fill Form</h4>
                        <p>Provide the command code, name, description, and optional screenshots.</p>
                    </div>
                    <div class="step">
                        <h4>Review</h4>
                        <p>Your submission will be reviewed by the community before being published.</p>
                    </div>
                </div>
            </section>

            <section id="best-practices">
                <h2>Best Practices</h2>
                <p>Follow these guidelines to create high-quality command submissions:</p>

                <h3>Command Quality</h3>
                <ul>
                    <li>Test your command thoroughly before submitting</li>
                    <li>Use clear, descriptive names</li>
                    <li>Handle errors gracefully</li>
                    <li>Follow Discord's Terms of Service</li>
                </ul>

                <h3>Documentation</h3>
                <ul>
                    <li>Write clear, detailed descriptions</li>
                    <li>Explain how to use the command</li>
                    <li>Mention any required permissions</li>
                    <li>Include setup instructions if needed</li>
                </ul>

                <h3>Screenshots</h3>
                <ul>
                    <li>Show the command in action</li>
                    <li>Include both the command and response</li>
                    <li>Use clear, readable images</li>
                    <li>Crop images to focus on relevant content</li>
                </ul>
            </section>

            <section id="guidelines">
                <h2>Community Guidelines</h2>
                <p>To maintain a positive community, please follow these guidelines:</p>

                <div class="callout success">
                    <div class="callout-title">Do</div>
                    <ul>
                        <li>Create original, useful commands</li>
                        <li>Provide helpful descriptions</li>
                        <li>Be respectful to other users</li>
                        <li>Report inappropriate content</li>
                    </ul>
                </div>

                <div class="callout warning">
                    <div class="callout-title">Don't</div>
                    <ul>
                        <li>Submit commands that violate Discord's ToS</li>
                        <li>Copy other users' commands without permission</li>
                        <li>Submit spam or low-quality content</li>
                        <li>Include malicious or harmful code</li>
                    </ul>
                </div>

                <h3>Reporting Issues</h3>
                <p>If you encounter problems or inappropriate content, please report it to the moderators. We're committed to maintaining a safe and helpful community.</p>
            </section>
        </main>
    </div>

    <script>
        // Smooth scrolling for sidebar links
        document.querySelectorAll('.sidebar-nav a').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const target = document.querySelector(link.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth' });

                    // Update active link
                    document.querySelectorAll('.sidebar-nav a').forEach(l => l.classList.remove('active'));
                    link.classList.add('active');
                }
            });
        });

        // Copy code functionality
        function copyCode(button) {
            const codeBlock = button.nextElementSibling;
            const text = codeBlock.textContent;

            navigator.clipboard.writeText(text).then(() => {
                const originalIcon = button.innerHTML;
                button.innerHTML = '<i class="fas fa-check"></i>';
                button.style.background = 'rgba(34, 197, 94, 0.2)';

                setTimeout(() => {
                    button.innerHTML = originalIcon;
                    button.style.background = 'rgba(255, 255, 255, 0.1)';
                }, 2000);
            });
        }

        // Update active sidebar link on scroll
        window.addEventListener('scroll', () => {
            const sections = document.querySelectorAll('section[id]');
            const scrollPos = window.scrollY + 150;

            sections.forEach(section => {
                const top = section.offsetTop;
                const bottom = top + section.offsetHeight;
                const id = section.getAttribute('id');

                if (scrollPos >= top && scrollPos <= bottom) {
                    document.querySelectorAll('.sidebar-nav a').forEach(link => {
                        link.classList.remove('active');
                        if (link.getAttribute('href') === '#' + id) {
                            link.classList.add('active');
                        }
                    });
                }
            });
        });

        // Load user info on page load
        document.addEventListener('DOMContentLoaded', async () => {
            const sessionToken = localStorage.getItem('sessionToken');
            if (!sessionToken) return;

            try {
                const response = await fetch('/api/get-user', {
                    headers: {
                        'Authorization': 'Bearer ' + sessionToken
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    displayUserInfo(data.user);
                } else {
                    // Invalid session, clear it
                    localStorage.removeItem('sessionToken');
                    localStorage.removeItem('userData');
                }
            } catch (error) {
                console.error('Error loading user info:', error);
            }
        });

        function displayUserInfo(user) {
            const userInfo = document.getElementById('user-info');
            const userAvatar = document.getElementById('user-avatar');
            const userName = document.getElementById('user-name');
            const logoutBtn = document.getElementById('logout-btn');

            if (userInfo && userAvatar && userName) {
                userAvatar.src = user.avatar ?
                    'https://cdn.discordapp.com/avatars/' + user.id + '/' + user.avatar + '.png?size=64' :
                    'https://cdn.discordapp.com/embed/avatars/0.png';
                userName.textContent = user.username + '#' + user.discriminator;
                userInfo.classList.remove('hidden');

                if (logoutBtn) {
                    logoutBtn.addEventListener('click', () => {
                        localStorage.removeItem('sessionToken');
                        localStorage.removeItem('userData');
                        window.location.reload();
                    });
                }
            }
        }
    </script>
</body>
</html>`,
    '/': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Hub - Professional Discord Bot Development</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            line-height: 1.6;
            overflow-x: hidden;
        }

        /* Header */
        .header {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: rgba(10, 10, 10, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid #1a1a1a;
            z-index: 1000;
            padding: 1rem 0;
        }

        .nav {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 2rem;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: #ffffff;
            text-decoration: none;
        }

        .logo-icon {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, #ffffff, #cccccc);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            color: #000;
        }

        .nav-links {
            display: flex;
            gap: 2rem;
            list-style: none;
        }

        .nav-links a {
            color: #cccccc;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }

        .nav-links a:hover {
            color: #ffffff;
        }

        .user-nav {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-info-card {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 0.5rem 1rem;
        }

        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            border: 2px solid rgba(255, 255, 255, 0.2);
        }

        .user-details {
            display: flex;
            flex-direction: column;
            gap: 0.125rem;
        }

        .user-name {
            font-size: 0.875rem;
            font-weight: 600;
            color: #ffffff;
        }

        .user-status {
            font-size: 0.75rem;
            color: #888888;
        }

        .logout-btn {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #ef4444;
            padding: 0.375rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.375rem;
        }

        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.2);
            border-color: rgba(239, 68, 68, 0.5);
        }

        /* Hero Section */
        .hero {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
            background: radial-gradient(ellipse at center, #1a1a1a 0%, #0a0a0a 70%);
            position: relative;
            overflow: hidden;
        }

        .hero::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="%23333" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.1;
        }

        .hero-content {
            max-width: 800px;
            padding: 0 2rem;
            position: relative;
            z-index: 1;
        }

        .hero-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 0.5rem 1rem;
            border-radius: 50px;
            font-size: 0.875rem;
            font-weight: 500;
            margin-bottom: 2rem;
            backdrop-filter: blur(10px);
        }

        .hero h1 {
            font-size: clamp(2.5rem, 5vw, 4rem);
            font-weight: 700;
            margin-bottom: 1.5rem;
            background: linear-gradient(135deg, #ffffff, #cccccc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .hero p {
            font-size: 1.25rem;
            color: #cccccc;
            margin-bottom: 3rem;
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
        }

        .cta-buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 1rem 2rem;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 600;
            font-size: 1rem;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
        }

        .btn-primary {
            background: #ffffff;
            color: #000000;
        }

        .btn-primary:hover {
            background: #f0f0f0;
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(255, 255, 255, 0.1);
        }

        .btn-secondary {
            background: transparent;
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.5);
        }

        /* Features Section */
        .features {
            padding: 6rem 0;
            background: #0a0a0a;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
        }

        .section-header {
            text-align: center;
            margin-bottom: 4rem;
        }

        .section-title {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #ffffff, #cccccc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .section-subtitle {
            font-size: 1.125rem;
            color: #cccccc;
            max-width: 600px;
            margin: 0 auto;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }

        .feature-card {
            background: linear-gradient(135deg, #1a1a1a, #0f0f0f);
            border: 1px solid #2a2a2a;
            border-radius: 16px;
            padding: 2rem;
            transition: all 0.3s ease;
        }

        .feature-card:hover {
            transform: translateY(-5px);
            border-color: #3a3a3a;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }

        .feature-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #ffffff, #cccccc);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: #000;
            margin-bottom: 1.5rem;
        }

        .feature-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: #ffffff;
        }

        .feature-description {
            color: #cccccc;
            line-height: 1.6;
        }



        /* Footer */
        .footer {
            background: #0a0a0a;
            border-top: 1px solid #1a1a1a;
            padding: 3rem 0 2rem;
        }

        .footer-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .footer-section h3 {
            font-size: 1.125rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: #ffffff;
        }

        .footer-section ul {
            list-style: none;
        }

        .footer-section ul li {
            margin-bottom: 0.5rem;
        }

        .footer-section ul li a {
            color: #cccccc;
            text-decoration: none;
            transition: color 0.3s ease;
        }

        .footer-section ul li a:hover {
            color: #ffffff;
        }

        .footer-bottom {
            border-top: 1px solid #1a1a1a;
            padding-top: 2rem;
            text-align: center;
            color: #666666;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .nav {
                padding: 0 1rem;
            }

            .nav-links {
                display: none;
            }

            .hero-content {
                padding: 0 1rem;
            }

            .cta-buttons {
                flex-direction: column;
                align-items: center;
            }

            .btn {
                width: 100%;
                max-width: 300px;
                justify-content: center;
            }
        }

        /* Animations */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .hero-content > * {
            animation: fadeInUp 0.8s ease-out forwards;
        }

        .hero-content > *:nth-child(2) { animation-delay: 0.1s; }
        .hero-content > *:nth-child(3) { animation-delay: 0.2s; }
        .hero-content > *:nth-child(4) { animation-delay: 0.3s; }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <nav class="nav">
            <a href="/" class="logo">
                <div class="logo-icon">
                    <i class="fas fa-code"></i>
                </div>
                Code Hub
            </a>
            <ul class="nav-links">
                <li><a href="/">Features</a></li>
                <li><a href="/marketplace">Marketplace</a></li>
                <li><a href="/submit">Submit</a></li>
                <li><a href="/docs">Documentation</a></li>
            </ul>
            <div class="user-nav">
                <div id="user-info" class="user-info-card hidden">
                    <img id="user-avatar" class="user-avatar" alt="User Avatar">
                    <div class="user-details">
                        <div id="user-name" class="user-name"></div>
                        <div class="user-status">Authenticated</div>
                    </div>
                    <button id="logout-btn" class="logout-btn">
                        <i class="fas fa-sign-out-alt"></i>
                        Logout
                    </button>
                </div>
            </div>
        </nav>
    </header>

    <!-- Hero Section -->
    <section class="hero">
        <div class="hero-content">
            <div class="hero-badge">
                <i class="fas fa-robot"></i>
                BotGhost Command Marketplace
            </div>
            <h1>Share BotGhost Commands with Code Hub</h1>
            <p>The premier marketplace for BotGhost command codes. Discover, share, and import no-code Discord bot commands created by the community.</p>
            <div class="cta-buttons">
                <a href="/submit.html" class="btn btn-primary">
                    <i class="fas fa-upload"></i>
                    Submit Command
                </a>
                <a href="/marketplace" class="btn btn-secondary">
                    <i class="fas fa-store"></i>
                    Browse Marketplace
                </a>
            </div>
        </div>
    </section>



    <!-- Features Section -->
    <section class="features" id="features">
        <div class="container">
            <div class="section-header">
                <h2 class="section-title">BotGhost Command Sharing</h2>
                <p class="section-subtitle">Share and discover BotGhost command codes created by the community. No coding required - just copy, paste, and enhance your bot.</p>
            </div>
            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-mouse-pointer"></i>
                    </div>
                    <h3 class="feature-title">No Code Required</h3>
                    <p class="feature-description">All commands are created using BotGhost's visual editor. Simply copy the command code and import it into your BotGhost bot.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-copy"></i>
                    </div>
                    <h3 class="feature-title">One-Click Import</h3>
                    <p class="feature-description">Copy the command code and paste it directly into BotGhost's import feature. Your command will be ready to use instantly.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-puzzle-piece"></i>
                    </div>
                    <h3 class="feature-title">Ready-to-Use Commands</h3>
                    <p class="feature-description">Discover community-created commands for moderation, fun, utility, and more. All commands are tested by their creators and ready for your server.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-users"></i>
                    </div>
                    <h3 class="feature-title">Community Driven</h3>
                    <p class="feature-description">Created by BotGhost users, for BotGhost users. Share your own commands and discover what others have built.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-tags"></i>
                    </div>
                    <h3 class="feature-title">Organized Categories</h3>
                    <p class="feature-description">Find exactly what you need with organized categories: moderation, fun, utility, economy, music, and more.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-star"></i>
                    </div>
                    <h3 class="feature-title">Quality Assured</h3>
                    <p class="feature-description">All commands are reviewed and tested by the community. Ratings and reviews help you find the best commands.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <div class="footer-content">
                <div class="footer-section">
                    <h3>Code Hub</h3>
                    <p style="color: #cccccc; margin-top: 1rem;">Professional Discord bot development made simple. Join thousands of developers building better bots.</p>
                </div>
                <div class="footer-section">
                    <h3>Resources</h3>
                    <ul>
                        <li><a href="#docs">Documentation</a></li>
                        <li><a href="#api">API Reference</a></li>
                        <li><a href="#guides">Guides</a></li>
                        <li><a href="#examples">Examples</a></li>
                    </ul>
                </div>
                <div class="footer-section">
                    <h3>Community</h3>
                    <ul>
                        <li><a href="#discord">Discord Server</a></li>
                        <li><a href="#github">GitHub</a></li>
                        <li><a href="#twitter">Twitter</a></li>
                        <li><a href="#blog">Blog</a></li>
                    </ul>
                </div>
                <div class="footer-section">
                    <h3>Support</h3>
                    <ul>
                        <li><a href="#help">Help Center</a></li>
                        <li><a href="#contact">Contact Us</a></li>
                        <li><a href="#status">Status Page</a></li>
                        <li><a href="#enterprise">Enterprise</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <p>&copy; 2025 Code Hub. All rights reserved. Built with ❤️ for the Discord community.</p>
            </div>
        </div>
    </footer>

    <script>
        // Smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });

        // Header background on scroll
        window.addEventListener('scroll', () => {
            const header = document.querySelector('.header');
            if (window.scrollY > 100) {
                header.style.background = 'rgba(10, 10, 10, 0.98)';
            } else {
                header.style.background = 'rgba(10, 10, 10, 0.95)';
            }
        });

        // Load user info on page load
        document.addEventListener('DOMContentLoaded', async () => {
            const sessionToken = localStorage.getItem('sessionToken');
            if (!sessionToken) return;

            try {
                const response = await fetch('/api/get-user', {
                    headers: {
                        'Authorization': 'Bearer ' + sessionToken
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    displayUserInfo(data.user);
                } else {
                    // Invalid session, clear it
                    localStorage.removeItem('sessionToken');
                    localStorage.removeItem('userData');
                }
            } catch (error) {
                console.error('Error loading user info:', error);
            }
        });

        function displayUserInfo(user) {
            const userInfo = document.getElementById('user-info');
            const userAvatar = document.getElementById('user-avatar');
            const userName = document.getElementById('user-name');
            const logoutBtn = document.getElementById('logout-btn');

            if (userInfo && userAvatar && userName) {
                userAvatar.src = user.avatar ?
                    'https://cdn.discordapp.com/avatars/' + user.id + '/' + user.avatar + '.png?size=64' :
                    'https://cdn.discordapp.com/embed/avatars/0.png';
                userName.textContent = user.username + '#' + user.discriminator;
                userInfo.classList.remove('hidden');

                if (logoutBtn) {
                    logoutBtn.addEventListener('click', () => {
                        localStorage.removeItem('sessionToken');
                        localStorage.removeItem('userData');
                        window.location.reload();
                    });
                }
            }
        }
    </script>
</body>
</html>`,
    '/submit.html': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Submit Command - Code Hub</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            line-height: 1.6;
            min-height: 100vh;
        }

        /* Header */
        .header {
            background: rgba(10, 10, 10, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid #1a1a1a;
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .nav {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 2rem;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: #ffffff;
            text-decoration: none;
        }

        .logo-icon {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, #ffffff, #cccccc);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            color: #000;
        }

        .user-nav {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        /* Main Content */
        .main {
            max-width: 800px;
            margin: 0 auto;
            padding: 3rem 2rem;
        }

        .page-header {
            text-align: center;
            margin-bottom: 3rem;
        }

        .page-title {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            background: linear-gradient(135deg, #ffffff, #cccccc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .page-subtitle {
            font-size: 1.125rem;
            color: #cccccc;
            max-width: 600px;
            margin: 0 auto;
        }

        /* Cards */
        .card {
            background: linear-gradient(135deg, #1a1a1a, #0f0f0f);
            border: 1px solid #2a2a2a;
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            transition: all 0.3s ease;
        }

        .card:hover {
            border-color: #3a3a3a;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }

        /* Auth Section */
        .auth-card {
            text-align: center;
        }

        .auth-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #5865f2, #4752c4);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            color: white;
            margin: 0 auto 1.5rem;
        }

        .auth-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #ffffff;
        }

        .auth-description {
            color: #cccccc;
            margin-bottom: 2rem;
        }

        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 1rem 2rem;
            border-radius: 12px;
            text-decoration: none;
            font-weight: 600;
            font-size: 1rem;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }

        .btn-primary {
            background: #ffffff;
            color: #000000;
        }

        .btn-primary:hover {
            background: #f0f0f0;
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(255, 255, 255, 0.1);
        }

        .btn-secondary {
            background: transparent;
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.5);
        }

        .btn-discord {
            background: #5865f2;
            color: white;
        }

        .btn-discord:hover {
            background: #4752c4;
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(88, 101, 242, 0.3);
        }

        /* Form Elements */
        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-label {
            display: block;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #ffffff;
        }

        .form-input, .form-textarea {
            width: 100%;
            padding: 1rem;
            border: 1px solid #2a2a2a;
            background: #111111;
            color: #ffffff;
            border-radius: 12px;
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .form-input:focus, .form-textarea:focus {
            outline: none;
            border-color: #ffffff;
            box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.1);
        }

        /* Select specific styling */
        select.form-input {
            appearance: none;
            background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23ffffff' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6,9 12,15 18,9'%3e%3c/polyline%3e%3c/svg%3e");
            background-repeat: no-repeat;
            background-position: right 1rem center;
            background-size: 1rem;
            padding-right: 3rem;
            cursor: pointer;
        }

        select.form-input:hover {
            background-color: #111111;
        }

        select.form-input option {
            background-color: #111111;
            color: #ffffff;
        }

        .form-help {
            font-size: 0.875rem;
            color: #888888;
            margin-top: 0.5rem;
        }

        .file-upload {
            border: 2px dashed #2a2a2a;
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .file-upload:hover {
            border-color: #ffffff;
            background: rgba(255, 255, 255, 0.02);
        }

        .file-upload-icon {
            font-size: 2rem;
            color: #666666;
            margin-bottom: 1rem;
        }

        .file-upload-text {
            color: #cccccc;
            margin-bottom: 0.5rem;
        }

        .file-upload-help {
            font-size: 0.875rem;
            color: #888888;
        }

        /* User Info */
        .user-info-card {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 0.5rem 1rem;
        }

        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            border: 2px solid rgba(255, 255, 255, 0.2);
        }

        .user-details {
            display: flex;
            flex-direction: column;
            gap: 0.125rem;
        }

        .user-name {
            font-size: 0.875rem;
            font-weight: 600;
            color: #ffffff;
        }

        .user-status {
            font-size: 0.75rem;
            color: #888888;
        }

        .logout-btn {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #ef4444;
            padding: 0.375rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.375rem;
        }

        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.2);
            border-color: rgba(239, 68, 68, 0.5);
        }

        /* Loading */
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid #333333;
            border-top: 2px solid #ffffff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* States */
        .hidden {
            display: none !important;
            visibility: hidden !important;
        }

        /* Ensure user info is hidden by default */
        .user-info-card.hidden,
        .user-info.hidden {
            display: none !important;
            visibility: hidden !important;
        }

        /* Ensure initial states */
        #access-denied.hidden,
        #admin-dashboard.hidden {
            display: none !important;
        }

        #access-check {
            display: block;
        }

        /* Alerts */
        .alert {
            padding: 1rem;
            border-radius: 12px;
            margin-bottom: 1rem;
            border: 1px solid;
        }

        .alert-error {
            background: rgba(239, 68, 68, 0.1);
            border-color: rgba(239, 68, 68, 0.3);
            color: #fca5a5;
        }

        .alert-success {
            background: rgba(34, 197, 94, 0.1);
            border-color: rgba(34, 197, 94, 0.3);
            color: #86efac;
        }

        /* Success Section */
        .success-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #22c55e, #16a34a);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            color: white;
            margin: 0 auto 1.5rem;
        }

        .success-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #ffffff;
            text-align: center;
        }

        .success-description {
            color: #cccccc;
            margin-bottom: 2rem;
            text-align: center;
        }

        .success-actions {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }

        .nav-links {
            display: flex;
            gap: 2rem;
            list-style: none;
        }

        .nav-links a {
            color: #cccccc;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }

        .nav-links a:hover {
            color: #ffffff;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .nav {
                padding: 0 1rem;
            }

            .nav-links {
                display: none;
            }

            .main {
                padding: 2rem 1rem;
            }

            .card {
                padding: 1.5rem;
            }

            .success-actions {
                flex-direction: column;
            }

            .btn {
                width: 100%;
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <nav class="nav">
            <a href="/" class="logo">
                <div class="logo-icon">
                    <i class="fas fa-code"></i>
                </div>
                Code Hub
            </a>
            <ul class="nav-links">
                <li><a href="/">Features</a></li>
                <li><a href="/marketplace">Marketplace</a></li>
                <li><a href="/submit">Submit</a></li>
                <li><a href="/docs">Documentation</a></li>
            </ul>
            <div class="user-nav">
                <div id="user-info" class="user-info-card hidden">
                    <img id="user-avatar" class="user-avatar" alt="User Avatar">
                    <div class="user-details">
                        <div id="user-name" class="user-name"></div>
                        <div class="user-status">Authenticated</div>
                    </div>
                    <button id="logout-btn" class="logout-btn">
                        <i class="fas fa-sign-out-alt"></i>
                        Logout
                    </button>
                </div>
            </div>
        </nav>
    </header>

    <!-- Main Content -->
    <main class="main">
        <div class="page-header">
            <h1 class="page-title">Submit Your BotGhost Command</h1>
            <p class="page-subtitle">Share your BotGhost command codes with the community. Help other users discover and import amazing no-code commands for their bots.</p>
        </div>

        <!-- Authentication Section -->
        <div id="auth-section" class="card auth-card">
            <div class="auth-icon">
                <i class="fab fa-discord"></i>
            </div>
            <h2 class="auth-title">Connect with Discord</h2>
            <p class="auth-description">Authenticate with your Discord account to submit commands to the marketplace.</p>
            <button id="discord-login-btn" class="btn btn-discord">
                <i class="fab fa-discord"></i>
                <span>Login with Discord</span>
                <div id="auth-loading" class="loading hidden"></div>
            </button>
            <div id="auth-error" class="alert alert-error hidden"></div>
        </div>

        <!-- Submission Form -->
        <div id="form-section" class="card hidden">
            <h2 style="font-size: 1.5rem; font-weight: 600; margin-bottom: 1.5rem; color: #ffffff;">
                <i class="fas fa-code" style="margin-right: 0.5rem;"></i>
                Command Details
            </h2>
            <form id="submission-form">
                <div class="form-group">
                    <label class="form-label" for="command-code">
                        BotGhost Command Code <span style="color: #ef4444;">*</span>
                    </label>
                    <textarea
                        id="command-code"
                        name="commandCode"
                        class="form-textarea"
                        rows="4"
                        placeholder="CMD_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        required
                    ></textarea>
                    <div class="form-help">Export your command from BotGhost and paste the command code here (must start with CMD_)</div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="command-name">
                        Command Name <span style="color: #ef4444;">*</span>
                    </label>
                    <input
                        type="text"
                        id="command-name"
                        name="commandName"
                        class="form-input"
                        placeholder="e.g., /ticket, /moderation, /music"
                        required
                    >
                    <div class="form-help">The name of your BotGhost command as it appears in Discord</div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="command-description">
                        Description <span style="color: #ef4444;">*</span>
                    </label>
                    <textarea
                        id="command-description"
                        name="commandDescription"
                        class="form-textarea"
                        rows="5"
                        placeholder="Describe what your BotGhost command does, how to use it, and any special features..."
                        required
                    ></textarea>
                    <div class="form-help">Help others understand what your command does and how to use it effectively</div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="command-category">
                        Category <span style="color: #ef4444;">*</span>
                    </label>
                    <select
                        id="command-category"
                        name="commandCategory"
                        class="form-input"
                        required
                    >
                        <option value="">Select a category...</option>
                        <option value="moderation">🛡️ Moderation</option>
                        <option value="fun">🎉 Fun & Entertainment</option>
                        <option value="utility">🔧 Utility & Tools</option>
                        <option value="economy">💰 Economy & Currency</option>
                        <option value="music">🎵 Music & Audio</option>
                        <option value="games">🎮 Games & Activities</option>
                        <option value="social">👥 Social & Community</option>
                        <option value="automation">⚙️ Automation & Workflows</option>
                        <option value="information">📊 Information & Stats</option>
                        <option value="other">📦 Other</option>
                    </select>
                    <div class="form-help">Choose the category that best describes your command's primary function</div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="images">
                        Screenshots & Examples <span style="color: #888888;">(Optional)</span>
                    </label>
                    <div class="file-upload" onclick="document.getElementById('images').click()">
                        <div class="file-upload-icon">
                            <i class="fas fa-cloud-upload-alt"></i>
                        </div>
                        <div class="file-upload-text">Click to upload images or drag and drop</div>
                        <div class="file-upload-help">PNG, JPG, GIF up to 5MB each</div>
                        <input type="file" id="images" name="images" multiple accept="image/*" style="display: none;">
                    </div>
                    <div id="file-list" class="form-help" style="margin-top: 1rem;"></div>
                </div>

                <button type="submit" class="btn btn-primary" style="width: 100%;">
                    <i class="fas fa-paper-plane"></i>
                    <span>Submit Command</span>
                    <div id="submit-loading" class="loading hidden"></div>
                </button>
            </form>
            <div id="form-error" class="alert alert-error hidden"></div>
        </div>

        <!-- Success Section -->
        <div id="success-section" class="card hidden" style="text-align: center;">
            <div class="success-icon">
                <i class="fas fa-check"></i>
            </div>
            <h2 class="success-title">Submission Successful!</h2>
            <p class="success-description">Your command has been submitted for review. We'll notify you once it's approved and available in the marketplace.</p>
            <div class="success-actions">
                <button id="submit-another-btn" class="btn btn-primary">
                    <i class="fas fa-plus"></i>
                    Submit Another Command
                </button>
                <a href="/" class="btn btn-secondary">
                    <i class="fas fa-home"></i>
                    Back to Homepage
                </a>
            </div>
        </div>
    </main>

    <script>
        // Global variables
        let currentUser = null;
        let selectedFiles = [];

        // DOM elements
        const authSection = document.getElementById('auth-section');
        const userInfo = document.getElementById('user-info');
        const formSection = document.getElementById('form-section');
        const successSection = document.getElementById('success-section');
        const discordLoginBtn = document.getElementById('discord-login-btn');
        const authLoading = document.getElementById('auth-loading');
        const authError = document.getElementById('auth-error');
        const userName = document.getElementById('user-name');
        const userAvatar = document.getElementById('user-avatar');
        const logoutBtn = document.getElementById('logout-btn');
        const submissionForm = document.getElementById('submission-form');
        const submitLoading = document.getElementById('submit-loading');
        const formError = document.getElementById('form-error');
        const submitAnotherBtn = document.getElementById('submit-another-btn');
        const fileInput = document.getElementById('images');
        const fileList = document.getElementById('file-list');

        // Initialize
        document.addEventListener('DOMContentLoaded', async () => {
            // Check if user is already authenticated
            const sessionToken = localStorage.getItem('sessionToken');
            if (sessionToken) {
                try {
                    const response = await fetch('/api/get-user', {
                        headers: { 'Authorization': 'Bearer ' + sessionToken }
                    });

                    if (response.ok) {
                        const data = await response.json();
                        currentUser = data.user;
                        showForm();
                        displayUserInfo(data.user); // Always show user info in navbar
                    } else {
                        localStorage.removeItem('sessionToken');
                        localStorage.removeItem('userData');
                    }
                } catch (error) {
                    console.error('Auth check error:', error);
                    localStorage.removeItem('sessionToken');
                    localStorage.removeItem('userData');
                }
            }

            // Handle OAuth callback
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            const state = urlParams.get('state');

            if (code) {
                await handleOAuthCallback(code, state);
            }
        });

        // Display user info in navbar
        function displayUserInfo(user) {
            const userInfo = document.getElementById('user-info');
            const userAvatar = document.getElementById('user-avatar');
            const userName = document.getElementById('user-name');
            const logoutBtn = document.getElementById('logout-btn');

            if (userInfo && userAvatar && userName) {
                userAvatar.src = user.avatar ?
                    'https://cdn.discordapp.com/avatars/' + user.id + '/' + user.avatar + '.png?size=64' :
                    'https://cdn.discordapp.com/embed/avatars/0.png';
                userName.textContent = user.username + '#' + user.discriminator;
                userInfo.classList.remove('hidden');

                if (logoutBtn) {
                    // Remove existing event listeners to avoid duplicates
                    const newLogoutBtn = logoutBtn.cloneNode(true);
                    logoutBtn.parentNode.replaceChild(newLogoutBtn, logoutBtn);

                    newLogoutBtn.addEventListener('click', () => {
                        localStorage.removeItem('sessionToken');
                        localStorage.removeItem('userData');
                        window.location.reload();
                    });
                }
            }
        }

        // Discord login
        discordLoginBtn.addEventListener('click', async () => {
            authLoading.classList.remove('hidden');
            authError.classList.add('hidden');

            try {
                const response = await fetch('/api/discord-auth');
                const data = await response.json();

                if (data.authUrl) {
                    localStorage.setItem('oauthState', data.state);
                    window.location.href = data.authUrl;
                } else {
                    throw new Error('Failed to get auth URL');
                }
            } catch (error) {
                console.error('Discord login error:', error);
                showError(authError, 'Failed to initiate Discord login. Please try again.');
            } finally {
                authLoading.classList.add('hidden');
            }
        });

        // Handle OAuth callback
        async function handleOAuthCallback(code, state) {
            const storedState = localStorage.getItem('oauthState');

            if (state !== storedState) {
                showError(authError, 'Invalid OAuth state. Please try again.');
                return;
            }

            try {
                const response = await fetch('/api/discord-callback', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code, state }),
                });

                const data = await response.json();

                if (data.success) {
                    currentUser = data.user;
                    localStorage.setItem('sessionToken', data.sessionToken);
                    localStorage.removeItem('oauthState');

                    // Clean URL
                    window.history.replaceState({}, document.title, window.location.pathname);

                    showForm();
                    displayUserInfo(data.user); // Show user info in navbar
                } else {
                    throw new Error(data.error || 'Authentication failed');
                }
            } catch (error) {
                console.error('OAuth callback error:', error);
                showError(authError, 'Authentication failed. Please try again.');
            }
        }

        // Show form
        function showForm() {
            authSection.classList.add('hidden');
            userInfo.classList.remove('hidden');
            formSection.classList.remove('hidden');

            userName.textContent = currentUser.username + '#' + currentUser.discriminator;

            // Set user avatar
            if (currentUser.avatar) {
                userAvatar.src = 'https://cdn.discordapp.com/avatars/' + currentUser.id + '/' + currentUser.avatar + '.png';
            } else {
                userAvatar.src = 'https://cdn.discordapp.com/embed/avatars/' + (currentUser.discriminator % 5) + '.png';
            }
        }

        // Logout (this will be replaced by displayUserInfo function when user is authenticated)
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                localStorage.removeItem('sessionToken');
                localStorage.removeItem('userData');
                currentUser = null;
                selectedFiles = [];

                authSection.classList.remove('hidden');
                userInfo.classList.add('hidden');
                formSection.classList.add('hidden');
                successSection.classList.add('hidden');
            });
        }

        // File handling
        fileInput.addEventListener('change', handleFileSelection);

        function handleFileSelection(event) {
            const files = Array.from(event.target.files);
            selectedFiles = files;
            updateFileList();
        }

        function updateFileList() {
            if (selectedFiles.length === 0) {
                fileList.textContent = '';
                return;
            }

            const fileNames = selectedFiles.map(file => file.name + ' (' + formatFileSize(file.size) + ')');
            fileList.innerHTML = '<strong>Selected files:</strong> ' + fileNames.join(', ');
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Form submission
        submissionForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            submitLoading.classList.remove('hidden');
            formError.classList.add('hidden');

            try {
                const formData = new FormData();
                formData.append('commandCode', document.getElementById('command-code').value);
                formData.append('commandName', document.getElementById('command-name').value);
                formData.append('commandDescription', document.getElementById('command-description').value);
                formData.append('commandCategory', document.getElementById('command-category').value);

                const imageFiles = document.getElementById('images').files;
                for (let i = 0; i < imageFiles.length; i++) {
                    formData.append('images', imageFiles[i]);
                }

                const sessionToken = localStorage.getItem('sessionToken');
                const response = await fetch('/api/submit-command', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + sessionToken },
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    formSection.classList.add('hidden');
                    successSection.classList.remove('hidden');
                } else {
                    throw new Error(data.error || 'Submission failed');
                }
            } catch (error) {
                console.error('Submission error:', error);
                showError(formError, 'Submission failed: ' + error.message);
            } finally {
                submitLoading.classList.add('hidden');
            }
        });

        // Submit another
        submitAnotherBtn.addEventListener('click', () => {
            submissionForm.reset();
            selectedFiles = [];
            updateFileList();
            successSection.classList.add('hidden');
            formSection.classList.remove('hidden');
        });

        // Utility function to show errors
        function showError(element, message) {
            element.textContent = message;
            element.classList.remove('hidden');
        }

        // Drag and drop functionality
        const fileUpload = document.querySelector('.file-upload');

        fileUpload.addEventListener('dragover', (e) => {
            e.preventDefault();
            fileUpload.style.borderColor = '#ffffff';
            fileUpload.style.background = 'rgba(255, 255, 255, 0.05)';
        });

        fileUpload.addEventListener('dragleave', (e) => {
            e.preventDefault();
            fileUpload.style.borderColor = '#2a2a2a';
            fileUpload.style.background = 'transparent';
        });

        fileUpload.addEventListener('drop', (e) => {
            e.preventDefault();
            fileUpload.style.borderColor = '#2a2a2a';
            fileUpload.style.background = 'transparent';

            const files = Array.from(e.dataTransfer.files).filter(file => file.type.startsWith('image/'));
            if (files.length > 0) {
                selectedFiles = files;
                // Update the file input
                const dt = new DataTransfer();
                files.forEach(file => dt.items.add(file));
                fileInput.files = dt.files;
                updateFileList();
            }
        });

        // Form validation
        submissionForm.addEventListener('input', (e) => {
            if (e.target.id === 'command-code') {
                const value = e.target.value;
                if (value && !value.startsWith('CMD_')) {
                    e.target.style.borderColor = '#ef4444';
                } else {
                    e.target.style.borderColor = '#2a2a2a';
                }
            }
        });
    </script>
</body>
</html>`
  };

  return staticFiles[path] || null;
}

// Main request handler
export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    const corsResponse = handleCORS(request);
    if (corsResponse) return corsResponse;

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      let response;

      // Route API requests
      if (path.startsWith('/api/')) {
        switch (path) {
          case '/api/discord-auth':
            response = await handleDiscordAuth(request, env);
            break;

          case '/api/discord-callback':
            response = await handleDiscordCallback(request, env);
            break;

          case '/api/get-user':
            response = await handleGetUser(request, env);
            break;

          case '/api/submit-command':
            response = await handleSubmitCommand(request, env);
          break;

        case '/api/get-submissions':
          response = await handleGetSubmissions(request, env);
          break;

        case '/api/check-admin':
          response = await handleCheckAdmin(request, env);
          break;

        case '/api/update-submission-status':
          response = await handleUpdateSubmissionStatus(request, env);
            break;

        case '/api/delete-submission':
          response = await handleDeleteSubmission(request, env);
            break;

        case '/api/comments':
          if (request.method === 'GET') {
            response = await handleGetComments(request, env);
          } else if (request.method === 'POST') {
            response = await handleAddComment(request, env);
          } else {
            response = new Response(JSON.stringify({ error: 'Method not allowed' }), {
              status: 405,
              headers: { 'Content-Type': 'application/json' },
            });
          }
          break;

        case '/api/delete-comment':
          response = await handleDeleteComment(request, env);
          break;

        case '/api/ban-user':
          response = await handleBanUser(request, env);
          break;

        case '/api/banned-users':
          response = await handleGetBannedUsers(request, env);
          break;

          default:
            response = new Response(JSON.stringify({ error: 'API endpoint not found' }), {
              status: 404,
              headers: { 'Content-Type': 'application/json' },
            });
        }
      } else {
        // Serve static files
        const staticContent = await serveStaticFile(path);
        if (staticContent) {
          response = new Response(staticContent, {
            headers: { 'Content-Type': 'text/html' },
          });
        } else {
          response = new Response('Not Found', { status: 404 });
        }
      }

      return addCORSHeaders(response);
    } catch (error) {
      console.error('Worker error:', error);
      const errorResponse = new Response(JSON.stringify({
        error: 'Internal server error',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
      return addCORSHeaders(errorResponse);
    }
  },
};
