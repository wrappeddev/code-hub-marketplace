-- Cloudflare D1 Database Schema for Code Hub Marketplace

-- Submissions table
CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    command_code TEXT NOT NULL,
    command_name TEXT NOT NULL,
    command_description TEXT NOT NULL,
    submitted_by_user_id TEXT NOT NULL,
    submitted_by_username TEXT NOT NULL,
    submitted_by_discriminator TEXT NOT NULL,
    images TEXT, -- JSON array of image objects
    submitted_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reviewed_at TEXT,
    reviewed_by TEXT,
    review_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Users table (optional - for storing user data)
CREATE TABLE IF NOT EXISTS users (
    discord_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    discriminator TEXT NOT NULL,
    email TEXT,
    avatar TEXT,
    first_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    submission_count INTEGER DEFAULT 0,
    is_banned BOOLEAN DEFAULT FALSE
);

-- Categories table (for organizing commands)
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    icon TEXT,
    color TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Tags table (for tagging commands)
CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    color TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Submission categories junction table
CREATE TABLE IF NOT EXISTS submission_categories (
    submission_id TEXT,
    category_id INTEGER,
    PRIMARY KEY (submission_id, category_id),
    FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
);

-- Submission tags junction table
CREATE TABLE IF NOT EXISTS submission_tags (
    submission_id TEXT,
    tag_id INTEGER,
    PRIMARY KEY (submission_id, tag_id),
    FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- Votes/ratings table (for community voting)
CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    vote_type TEXT NOT NULL CHECK (vote_type IN ('up', 'down')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(submission_id, user_id),
    FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE CASCADE
);

-- Comments table (for feedback on submissions)
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    content TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (submission_id) REFERENCES submissions(id) ON DELETE CASCADE
);

-- Admin actions log
CREATE TABLE IF NOT EXISTS admin_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_type TEXT NOT NULL, -- 'submission', 'user', 'comment', etc.
    target_id TEXT NOT NULL,
    details TEXT, -- JSON object with action details
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_submissions_submitted_at ON submissions(submitted_at);
CREATE INDEX IF NOT EXISTS idx_submissions_user ON submissions(submitted_by_user_id);
CREATE INDEX IF NOT EXISTS idx_votes_submission ON votes(submission_id);
CREATE INDEX IF NOT EXISTS idx_comments_submission ON comments(submission_id);
CREATE INDEX IF NOT EXISTS idx_users_last_seen ON users(last_seen_at);

-- Insert default categories
INSERT OR IGNORE INTO categories (name, description, icon, color) VALUES
('Moderation', 'Commands for server moderation and management', 'fas fa-shield-alt', '#ef4444'),
('Utility', 'Helpful utility commands for everyday use', 'fas fa-tools', '#3b82f6'),
('Fun', 'Entertainment and fun commands', 'fas fa-smile', '#f59e0b'),
('Music', 'Music and audio related commands', 'fas fa-music', '#8b5cf6'),
('Economy', 'Virtual economy and currency commands', 'fas fa-coins', '#10b981'),
('Games', 'Gaming and interactive commands', 'fas fa-gamepad', '#ec4899'),
('Information', 'Commands that provide information', 'fas fa-info-circle', '#6b7280'),
('Automation', 'Automated tasks and workflows', 'fas fa-robot', '#14b8a6');

-- Insert default tags
INSERT OR IGNORE INTO tags (name, color) VALUES
('slash-command', '#3b82f6'),
('prefix-command', '#8b5cf6'),
('admin-only', '#ef4444'),
('premium', '#f59e0b'),
('beginner-friendly', '#10b981'),
('advanced', '#ec4899'),
('database-required', '#6b7280'),
('api-integration', '#14b8a6');

-- Trigger to update updated_at timestamp
CREATE TRIGGER IF NOT EXISTS update_submissions_timestamp 
    AFTER UPDATE ON submissions
    BEGIN
        UPDATE submissions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS update_comments_timestamp 
    AFTER UPDATE ON comments
    BEGIN
        UPDATE comments SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

-- Trigger to update user submission count
CREATE TRIGGER IF NOT EXISTS increment_user_submission_count
    AFTER INSERT ON submissions
    BEGIN
        INSERT OR REPLACE INTO users (discord_id, username, discriminator, submission_count, last_seen_at)
        VALUES (
            NEW.submitted_by_user_id,
            NEW.submitted_by_username,
            NEW.submitted_by_discriminator,
            COALESCE((SELECT submission_count FROM users WHERE discord_id = NEW.submitted_by_user_id), 0) + 1,
            CURRENT_TIMESTAMP
        );
    END;
