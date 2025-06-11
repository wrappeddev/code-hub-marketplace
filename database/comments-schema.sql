-- Comments table for command reviews and feedback
CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    submission_id TEXT NOT NULL,
    content TEXT NOT NULL,
    rating INTEGER,
    author_id TEXT NOT NULL,
    author_username TEXT NOT NULL,
    author_discriminator TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Index for faster queries
CREATE INDEX IF NOT EXISTS idx_comments_submission_id ON comments(submission_id);
CREATE INDEX IF NOT EXISTS idx_comments_created_at ON comments(created_at);
CREATE INDEX IF NOT EXISTS idx_comments_author_id ON comments(author_id);
