#!/usr/bin/env node

// Migration script to create/update comments table with correct schema
const { execSync } = require('child_process');

console.log('🔄 Migrating comments table schema...\n');

// Function to run commands and handle errors
function runCommand(command, description) {
  console.log(`📋 ${description}...`);
  try {
    const output = execSync(command, { encoding: 'utf8', stdio: 'inherit' });
    console.log(`✅ ${description} completed\n`);
    return output;
  } catch (error) {
    console.error(`❌ ${description} failed:`, error.message);
    return null;
  }
}

// Create comments table with correct schema for local development
console.log('🗄️ Setting up comments table for local development...');
const localCommentsCommand = `npx wrangler d1 execute marketplace-db --local --file=database/comments-schema.sql`;
runCommand(localCommentsCommand, 'Creating comments table in local database');

// Create banned_users table for local development
console.log('🗄️ Setting up banned_users table for local development...');
const localBannedUsersCommand = `npx wrangler d1 execute marketplace-db --local --command="CREATE TABLE IF NOT EXISTS banned_users (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, username TEXT NOT NULL, discriminator TEXT NOT NULL, banned_by TEXT NOT NULL, banned_at TEXT NOT NULL, reason TEXT);"`;
runCommand(localBannedUsersCommand, 'Creating banned_users table in local database');

// Create comments table with correct schema for production
console.log('🗄️ Setting up comments table for production...');
const prodCommentsCommand = `npx wrangler d1 execute marketplace-db-prod --env production --remote --file=database/comments-schema.sql`;
runCommand(prodCommentsCommand, 'Creating comments table in production database');

// Create banned_users table for production
console.log('🗄️ Setting up banned_users table for production...');
const prodBannedUsersCommand = `npx wrangler d1 execute marketplace-db-prod --env production --remote --command="CREATE TABLE IF NOT EXISTS banned_users (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, username TEXT NOT NULL, discriminator TEXT NOT NULL, banned_by TEXT NOT NULL, banned_at TEXT NOT NULL, reason TEXT);"`;
runCommand(prodBannedUsersCommand, 'Creating banned_users table in production database');

// Update submissions table to include command_category if missing
console.log('🗄️ Updating submissions table schema...');
const updateSubmissionsLocal = `npx wrangler d1 execute marketplace-db --local --command="ALTER TABLE submissions ADD COLUMN command_category TEXT;"`;
const updateSubmissionsProd = `npx wrangler d1 execute marketplace-db-prod --env production --remote --command="ALTER TABLE submissions ADD COLUMN command_category TEXT;"`;

runCommand(updateSubmissionsLocal, 'Adding command_category column to local submissions table');
runCommand(updateSubmissionsProd, 'Adding command_category column to production submissions table');

console.log('🎉 Migration completed!');
console.log('\n📝 Next steps:');
console.log('1. Deploy the updated worker:');
console.log('   npx wrangler deploy --env production');
console.log('\n2. Test comment functionality on both local and production environments');
