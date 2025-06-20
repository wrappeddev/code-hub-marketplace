# Code Hub Marketplace

> **⚠️ SHOWCASE PROJECT - NOT FOR USE ⚠️**
>
> **This is a portfolio/showcase piece. This code is NOT open source and is NOT free to use.**
> **Any use, copying, or modification requires explicit documented permission from wrappeddev.**
> **See [LICENSE](LICENSE) for complete terms and restrictions.**

A professional Discord bot command marketplace built with Cloudflare Workers, D1 database, and R2 storage. Share and discover BotGhost commands with the community.

![Code Hub Banner](Code_Hub_Banner_1.png)

## 🚨 IMPORTANT LEGAL NOTICE

**THIS IS A SHOWCASE/PORTFOLIO PROJECT**

- ❌ **NOT open source**
- ❌ **NOT free to use**
- ❌ **NOT available for copying**
- ❌ **Commercial use PROHIBITED**
- ❌ **Redistribution PROHIBITED**

**✅ Viewing for educational/evaluation purposes only**

**📧 Contact wrappeddev at https://github.com/wrappeddev for permission before any use beyond viewing**

## ✨ Features

- **🔐 Discord OAuth Authentication** - Secure login with Discord
- **📝 Command Submission** - Submit BotGhost commands with descriptions and images
- **🛒 Marketplace** - Browse and search approved commands
- **⭐ Rating System** - Rate and review commands
- **💬 Comments** - Community feedback and discussions
- **👨‍💼 Admin Dashboard** - Moderate submissions and manage users
- **🚫 User Management** - Ban/unban users and delete comments
- **📱 Responsive Design** - Works on desktop and mobile
- **⚡ Fast & Scalable** - Built on Cloudflare's edge network

## 🏗️ Architecture

- **Frontend**: Embedded HTML/CSS/JS in Cloudflare Worker
- **Backend**: Cloudflare Workers (Serverless)
- **Database**: Cloudflare D1 (SQLite)
- **File Storage**: Cloudflare R2 (S3-compatible)
- **Authentication**: Discord OAuth 2.0

## 🚀 Quick Start

### Prerequisites

- [Node.js](https://nodejs.org/) (v18 or later)
- [Cloudflare account](https://cloudflare.com/)
- [Discord application](https://discord.com/developers/applications) for OAuth

### 1. Clone the Repository

```bash
git clone https://github.com/wrappeddev/code-hub-marketplace.git
cd code-hub-marketplace
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Set Up Cloudflare

1. **Login to Cloudflare:**
   ```bash
   npx wrangler login
   ```

2. **Create D1 Database:**
   ```bash
   npx wrangler d1 create marketplace-db
   ```
   Copy the database ID and update `wrangler.toml`

3. **Create R2 Bucket:**
   ```bash
   npx wrangler r2 bucket create marketplace-uploads
   ```

4. **Initialize Database Schema:**
   ```bash
   npx wrangler d1 execute marketplace-db --local --file=database/schema.sql
   npx wrangler d1 execute marketplace-db --local --file=database/comments-schema.sql
   ```

### 4. Configure Discord OAuth

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application
3. Go to OAuth2 settings
4. Add redirect URIs:
   - `http://localhost:8787/submit` (development)
   - `http://localhost:8787/marketplace` (development)
   - Your production URLs when deploying

### 5. Update Configuration

Edit `wrangler.toml` with your values:

```toml
# Replace with your actual values
DISCORD_CLIENT_ID = "your-discord-client-id"
DISCORD_CLIENT_SECRET = "your-discord-client-secret"
ADMIN_DISCORD_IDS = "your-discord-user-id"
database_id = "your-database-id"
```

### 6. Run Development Server

```bash
npx wrangler dev
```

Visit `http://localhost:8787` to see your marketplace!

## 📦 Deployment

### Deploy to Production

1. **Set up production database:**
   ```bash
   npx wrangler d1 create marketplace-db-prod
   ```

2. **Initialize production schema:**
   ```bash
   npx wrangler d1 execute marketplace-db-prod --remote --file=database/schema.sql
   npx wrangler d1 execute marketplace-db-prod --remote --file=database/comments-schema.sql
   ```

3. **Create production R2 bucket:**
   ```bash
   npx wrangler r2 bucket create marketplace-uploads-prod
   ```

4. **Update production config in `wrangler.toml`**

5. **Deploy:**
   ```bash
   npx wrangler deploy --env production
   ```

## 🛠️ Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run deploy` - Deploy to production
- `npm run migrate` - Run database migrations
- `npm run setup` - Initial development setup

### Database Management

**View submissions:**
```bash
npx wrangler d1 execute marketplace-db --local --command="SELECT * FROM submissions"
```

**View comments:**
```bash
npx wrangler d1 execute marketplace-db --local --command="SELECT * FROM comments"
```

**Reset database:**
```bash
npx wrangler d1 execute marketplace-db --local --file=database/schema.sql
```

### Project Structure

```
code-hub-marketplace/
├── worker/
│   └── index.js          # Main Cloudflare Worker
├── database/
│   ├── schema.sql        # Main database schema
│   └── comments-schema.sql # Comments table schema
├── migrate-comments.js   # Database migration script
├── wrangler.toml        # Cloudflare configuration
├── package.json         # Dependencies and scripts
└── README.md           # This file
```

## � API Endpoints

### Authentication
- `GET /api/discord-auth` - Initiate Discord OAuth flow
- `POST /api/discord-callback` - Handle OAuth callback
- `GET /api/get-user` - Get current authenticated user
- `GET /api/check-admin` - Check if user is admin

### Submissions
- `POST /api/submit-command` - Submit a new command
- `GET /api/get-submissions` - Get submissions (with status filter)
- `POST /api/update-submission-status` - Update submission status (admin)
- `DELETE /api/delete-submission` - Delete submission (admin)

### Comments
- `GET /api/comments` - Get comments for a submission
- `POST /api/comments` - Add a comment to a submission
- `DELETE /api/delete-comment` - Delete a comment (admin)

### User Management
- `POST /api/ban-user` - Ban a user (admin)
- `GET /api/get-banned-users` - Get banned users list (admin)

## 🔒 Security Features

- **Discord OAuth 2.0** - Secure authentication
- **Session Management** - JWT-like session tokens with expiration
- **Admin Controls** - Role-based access control
- **User Banning** - Prevent banned users from commenting
- **CSRF Protection** - State parameter in OAuth flow
- **Input Validation** - Server-side validation of all inputs

## 🎨 Customization

### Styling
The UI is built with custom CSS embedded in the worker. Key style sections:
- **Dark Theme** - Professional black/white color scheme
- **Responsive Grid** - Adaptive command card layout
- **Interactive Elements** - Hover effects and transitions

### Adding New Features
1. **New API Endpoints** - Add handlers in `worker/index.js`
2. **Database Changes** - Update schema files and run migrations
3. **UI Components** - Modify the embedded HTML/CSS/JS

## 🚨 Troubleshooting

### Common Issues

**OAuth Redirect Mismatch:**
```
Error: redirect_uri_mismatch
```
- Ensure Discord app redirect URIs match exactly
- Check both development and production URLs

**Database Errors:**
```
Error: no such table: comments
```
- Run the migration script: `npm run migrate`
- Ensure both schema files are executed

**Permission Errors:**
```
Error: Admin access required
```
- Check your Discord user ID is in `ADMIN_DISCORD_IDS`
- Verify environment variables are set correctly

### Debug Mode

Enable debug logging by checking Cloudflare Worker logs:
```bash
npx wrangler tail
```

## ⚠️ USAGE RESTRICTIONS

**BEFORE VIEWING THIS CODE, PLEASE READ:**

This repository contains proprietary code that is **NOT** available for use, copying, or distribution. By viewing this code, you agree to the following terms:

1. **NO COPYING** - You may not copy any portion of this code
2. **NO MODIFICATION** - You may not create derivative works
3. **NO DISTRIBUTION** - You may not share or redistribute this code
4. **NO COMMERCIAL USE** - This code cannot be used for any commercial purpose
5. **VIEWING ONLY** - Code may only be viewed for educational/evaluation purposes

**To use any part of this code, you MUST obtain explicit written permission from wrappeddev.**

## 🚫 Contributing

**Contributions are NOT accepted** for this showcase project. This is a closed-source portfolio piece.

If you're interested in collaborating or licensing this code, please contact the author directly.

## 📄 License

**This project is NOT open source.**

This project uses a **SHOWCASE LICENSE** - see the [LICENSE](LICENSE) file for complete terms.

**Summary:**
- ❌ NOT free to use
- ❌ NOT open source
- ❌ Requires explicit permission for any use
- ✅ Viewing for educational purposes only

## 🙏 Acknowledgments

- [Cloudflare Workers](https://workers.cloudflare.com/) - Serverless platform
- [Discord API](https://discord.com/developers/docs) - Authentication provider
- [BotGhost](https://botghost.com/) - No-code Discord bot platform

---

**Made with ❤️ for the Discord bot community**
