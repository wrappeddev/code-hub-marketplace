#!/usr/bin/env node

// Development setup script for Code Hub Marketplace

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🚀 Code Hub Marketplace - Development Setup\n');

// Check if .env exists
if (!fs.existsSync('.env')) {
  console.log('📝 Creating .env file from template...');
  fs.copyFileSync('.env.example', '.env');
  console.log('✅ .env file created. Please fill in your values.\n');
} else {
  console.log('✅ .env file already exists.\n');
}

// Check if user is logged into Cloudflare
console.log('🔐 Checking Cloudflare authentication...');
try {
  execSync('npx wrangler whoami', { stdio: 'pipe' });
  console.log('✅ Already logged into Cloudflare.\n');
} catch (error) {
  console.log('❌ Not logged into Cloudflare. Please run:');
  console.log('   npx wrangler login\n');
  process.exit(1);
}

// Function to run command and capture output
function runCommand(command, description) {
  console.log(`🔧 ${description}...`);
  try {
    const output = execSync(command, { encoding: 'utf8', stdio: 'pipe' });
    return output;
  } catch (error) {
    console.log(`❌ Failed: ${error.message}`);
    return null;
  }
}

// Check if D1 database exists
console.log('🗄️  Checking D1 database...');
try {
  const databases = execSync('npx wrangler d1 list', { encoding: 'utf8' });
  if (databases.includes('marketplace-db')) {
    console.log('✅ D1 database "marketplace-db" already exists.\n');
  } else {
    console.log('📦 Creating D1 database...');
    const createOutput = execSync('npx wrangler d1 create marketplace-db', { encoding: 'utf8' });
    console.log('✅ D1 database created!\n');
    
    // Extract database ID from output
    const dbIdMatch = createOutput.match(/database_id = "([^"]+)"/);
    if (dbIdMatch) {
      const dbId = dbIdMatch[1];
      console.log(`📋 Database ID: ${dbId}`);
      console.log('⚠️  Please update wrangler.toml with this database ID.\n');
    }
  }
} catch (error) {
  console.log(`❌ Error checking D1 database: ${error.message}\n`);
}

// Check if R2 bucket exists
console.log('🪣 Checking R2 bucket...');
try {
  const buckets = execSync('npx wrangler r2 bucket list', { encoding: 'utf8' });
  if (buckets.includes('marketplace-uploads')) {
    console.log('✅ R2 bucket "marketplace-uploads" already exists.\n');
  } else {
    console.log('📦 Creating R2 bucket...');
    execSync('npx wrangler r2 bucket create marketplace-uploads');
    console.log('✅ R2 bucket created!\n');
  }
} catch (error) {
  console.log(`❌ Error checking R2 bucket: ${error.message}\n`);
}

// Initialize database schema
console.log('🏗️  Initializing database schema...');
try {
  execSync('npx wrangler d1 execute marketplace-db --local --file=database/schema.sql');
  console.log('✅ Local database schema initialized!\n');
} catch (error) {
  console.log(`❌ Error initializing schema: ${error.message}\n`);
}

// Display next steps
console.log('🎉 Setup complete! Next steps:\n');
console.log('1. 📝 Fill in your .env file with Discord OAuth credentials');
console.log('2. 🔧 Update wrangler.toml with your actual database ID (if needed)');
console.log('3. 🚀 Start development:');
console.log('   npm run dev:worker    # Start Cloudflare Worker (API)');
console.log('   npm run dev           # Start Netlify Dev (Frontend)');
console.log('\n4. 🌐 Access your app:');
console.log('   Worker API: http://localhost:8787');
console.log('   Frontend:   http://localhost:8888');
console.log('\n5. 📚 Read setup.md for detailed instructions');

console.log('\n🔗 Useful commands:');
console.log('   npx wrangler d1 execute marketplace-db --local --command="SELECT * FROM submissions"');
console.log('   npx wrangler r2 object list marketplace-uploads');
console.log('   npx wrangler tail  # View Worker logs');

console.log('\n✨ Happy coding!');
