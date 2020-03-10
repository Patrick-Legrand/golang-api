CREATE TABLE IF NOT EXISTS "schema_migration" (
"version" TEXT NOT NULL
);
CREATE UNIQUE INDEX "schema_migration_version_idx" ON "schema_migration" (version);
CREATE TABLE IF NOT EXISTS "users" (
"id" TEXT PRIMARY KEY,
"email" TEXT NOT NULL,
"password_hash" TEXT NOT NULL,
"created_at" DATETIME NOT NULL,
"updated_at" DATETIME NOT NULL
);
