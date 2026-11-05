import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

// Groups (docs/v0.2.md, "Groups"). Apps see the group names in the `groups`
// claim, so renaming a group is a breaking change for them.

export interface Group {
  id: string;
  name: string;
  description: string;
  // Set by a SCIM client for its own matching.
  externalId: string | null;
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export class GroupStore {
  constructor(private readonly db: DatabaseSync) {}

  create(name: string, description = ''): Group {
    if (!NAME.test(name)) throw new Error('use 1-64 letters, digits, dots, hyphens or underscores for a group name');
    const id = randomUUID();
    this.db.prepare('INSERT INTO groups (id, name, description) VALUES (?, ?, ?)').run(id, name, description);
    return { id, name, description, externalId: null };
  }

  findById(id: string): Group | undefined {
    return this.db.prepare('SELECT id, name, description, external_id AS externalId FROM groups WHERE id = ?').get(id) as Group | undefined;
  }

  setExternalId(id: string, externalId: string | null): void {
    this.db.prepare('UPDATE groups SET external_id = ? WHERE id = ?').run(externalId, id);
  }

  findByExternalId(externalId: string): Group | undefined {
    return this.db.prepare('SELECT id, name, description, external_id AS externalId FROM groups WHERE external_id = ?').get(externalId) as Group | undefined;
  }

  rename(id: string, name: string): void {
    if (!NAME.test(name)) throw new Error('use 1-64 letters, digits, dots, hyphens or underscores for a group name');
    this.db.prepare('UPDATE groups SET name = ? WHERE id = ?').run(name, id);
  }

  delete(id: string): boolean {
    return Number(this.db.prepare('DELETE FROM groups WHERE id = ?').run(id).changes) > 0;
  }

  // Replaces the members with exactly these users.
  setMembers(id: string, userIds: string[]): void {
    this.db.exec('BEGIN');
    try {
      this.db.prepare('DELETE FROM group_members WHERE group_id = ?').run(id);
      const add = this.db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)');
      for (const u of userIds) add.run(id, u);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  findByName(name: string): Group | undefined {
    return this.db.prepare('SELECT id, name, description, external_id AS externalId FROM groups WHERE name = ?').get(name) as Group | undefined;
  }

  list(): Group[] {
    return this.db.prepare('SELECT id, name, description, external_id AS externalId FROM groups ORDER BY name').all() as unknown as Group[];
  }

  // Returns false when the user was already a member.
  addMember(groupId: string, userId: string): boolean {
    return Number(this.db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)').run(groupId, userId).changes) > 0;
  }

  // Returns false when the user was not a member.
  removeMember(groupId: string, userId: string): boolean {
    return Number(this.db.prepare('DELETE FROM group_members WHERE group_id = ? AND user_id = ?').run(groupId, userId).changes) > 0;
  }

  members(groupId: string): { id: string; email: string; name: string }[] {
    return this.db
      .prepare('SELECT u.id, u.email, u.name FROM group_members m JOIN users u ON u.id = m.user_id WHERE m.group_id = ? ORDER BY u.email')
      .all(groupId) as unknown as { id: string; email: string; name: string }[];
  }

  // Group names of a user, sorted, for the `groups` claim.
  namesOf(userId: string): string[] {
    const rows = this.db
      .prepare('SELECT g.name FROM group_members m JOIN groups g ON g.id = m.group_id WHERE m.user_id = ? ORDER BY g.name')
      .all(userId) as { name: string }[];
    return rows.map((r) => r.name);
  }
}
