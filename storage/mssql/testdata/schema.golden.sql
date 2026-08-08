IF OBJECT_ID(N'[parent]', N'U') IS NULL
BEGIN
  CREATE TABLE [parent] (
    [id] VARCHAR(36) NOT NULL PRIMARY KEY,
    [created] DATETIME2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    [__single_present__created] SMALLINT NOT NULL DEFAULT 0,
    [email] VARCHAR(255) NOT NULL,
    [__single_present__email] SMALLINT NOT NULL DEFAULT 0
  )
END;
IF OBJECT_ID(N'[child]', N'U') IS NULL
BEGIN
  CREATE TABLE [child] (
    [id] VARCHAR(36) NOT NULL PRIMARY KEY,
    [metadata] VARCHAR(8000),
    [__single_present__metadata] SMALLINT NOT NULL DEFAULT 0,
    [parentId] VARCHAR(36) NOT NULL,
    [__single_present__parentId] SMALLINT NOT NULL DEFAULT 0
  )
END;
IF NOT EXISTS (
  SELECT 1 FROM sys.indexes
  WHERE [name] = N'single_parent_email_idx' AND [object_id] = OBJECT_ID(N'[parent]')
)
BEGIN
  CREATE UNIQUE INDEX [single_parent_email_idx] ON [parent] ([email])
END;
IF NOT EXISTS (
  SELECT 1 FROM sys.indexes
  WHERE [name] = N'single_child_parentId_idx' AND [object_id] = OBJECT_ID(N'[child]')
)
BEGIN
  CREATE INDEX [single_child_parentId_idx] ON [child] ([parentId])
END;
IF NOT EXISTS (
  SELECT 1 FROM sys.foreign_keys
  WHERE [name] = N'single_child_parentId_fk' AND [parent_object_id] = OBJECT_ID(N'[child]')
)
BEGIN
  ALTER TABLE [child] WITH CHECK ADD CONSTRAINT [single_child_parentId_fk] FOREIGN KEY ([parentId]) REFERENCES [parent] ([id]) ON DELETE CASCADE
END;
