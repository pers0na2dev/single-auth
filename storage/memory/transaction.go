package memory

import (
	"context"
	"fmt"
	"reflect"

	"github.com/pers0na2dev/single-auth/storage"
)

// Transaction runs against an isolated copy. A successful callback merges only
// its base-to-working delta into the live state, preserving unrelated writes
// that completed concurrently. A failed or cancelled callback discards it.
func (a *Adapter) Transaction(ctx context.Context, callback func(storage.TransactionAdapter) error) error {
	if callback == nil {
		return fmt.Errorf("memory: transaction callback is nil")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	a.database.mu.RLock()
	base := cloneTables(a.database.tables)
	working := cloneTables(a.database.tables)
	a.database.mu.RUnlock()

	transactionDB := &database{tables: working}
	transaction := &transactionAdapter{executor: &executor{database: transactionDB, config: a.config}}
	if err := callback(transaction); err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}

	transactionDB.mu.RLock()
	completed := cloneTables(transactionDB.tables)
	transactionDB.mu.RUnlock()
	a.database.mu.Lock()
	merged := cloneTables(a.database.tables)
	mergeTransaction(merged, base, completed)
	if err := validateUniqueTables(a.config.schema, merged); err != nil {
		a.database.mu.Unlock()
		return err
	}
	replaceTables(a.database.tables, merged)
	a.database.mu.Unlock()
	return nil
}

func replaceTables(target, replacement map[string][]storage.Record) {
	for model := range target {
		if _, exists := replacement[model]; !exists {
			delete(target, model)
		}
	}
	for model, rows := range replacement {
		target[model] = cloneRows(rows)
	}
}

func mergeTransaction(live, base, completed map[string][]storage.Record) {
	models := make(map[string]struct{}, len(base)+len(completed))
	for model := range base {
		models[model] = struct{}{}
	}
	for model := range completed {
		models[model] = struct{}{}
	}
	for model := range models {
		completedRows, exists := completed[model]
		if !exists {
			delete(live, model)
			continue
		}
		baseByID := indexByID(base[model])
		completedByID := indexByID(completedRows)
		liveRows := live[model]
		merged := make([]storage.Record, 0, len(liveRows)+len(completedRows))
		placed := make(map[string]struct{}, len(liveRows))

		for _, liveRow := range liveRows {
			identity := rowIdentity(liveRow)
			baseRow, existedAtStart := baseByID[identity]
			completedRow, existsAfter := completedByID[identity]
			if existedAtStart && !existsAfter {
				continue
			}
			if existsAfter && rowChanged(baseRow, completedRow, existedAtStart) {
				merged = append(merged, cloneRecord(completedRow))
			} else {
				merged = append(merged, cloneRecord(liveRow))
			}
			placed[identity] = struct{}{}
		}
		for _, completedRow := range completedRows {
			identity := rowIdentity(completedRow)
			_, existedAtStart := baseByID[identity]
			_, alreadyPlaced := placed[identity]
			if !existedAtStart && !alreadyPlaced {
				merged = append(merged, cloneRecord(completedRow))
			}
		}
		live[model] = merged
	}
}

func indexByID(rows []storage.Record) map[string]storage.Record {
	indexed := make(map[string]storage.Record, len(rows))
	for _, row := range rows {
		indexed[rowIdentity(row)] = row
	}
	return indexed
}

func rowIdentity(row storage.Record) string {
	return fmt.Sprintf("%T:%v", row["id"], row["id"])
}

func rowChanged(base, completed storage.Record, existedAtStart bool) bool {
	return !existedAtStart || !reflect.DeepEqual(base, completed)
}
