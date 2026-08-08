SET FOREIGN_KEY_CHECKS = 0;
CREATE TABLE IF NOT EXISTS `parent` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `created` TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `__single_present__created` BOOLEAN NOT NULL DEFAULT FALSE,
  `email` VARCHAR(255) NOT NULL,
  `__single_present__email` BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE KEY `single_parent_email_idx` (`email`)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS `child` (
  `id` VARCHAR(36) NOT NULL PRIMARY KEY,
  `metadata` JSON,
  `__single_present__metadata` BOOLEAN NOT NULL DEFAULT FALSE,
  `parentId` VARCHAR(36) NOT NULL,
  `__single_present__parentId` BOOLEAN NOT NULL DEFAULT FALSE,
  KEY `single_child_parentId_idx` (`parentId`),
  CONSTRAINT `single_child_parentId_fk` FOREIGN KEY (`parentId`) REFERENCES `parent` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB;
SET FOREIGN_KEY_CHECKS = 1;
