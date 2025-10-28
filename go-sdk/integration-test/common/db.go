package common

import (
	"fmt"
	"math/rand"
	"os"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/storage"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type TestSqlProvider struct {
	Db *gorm.DB
}

func (p *TestSqlProvider) DB() *gorm.DB {
	return p.Db
}

func (p *TestSqlProvider) Close() {}

func NewSqliteStorage(t *testing.T) (*os.File, core.Storage, *gorm.DB, string) {
	seq := rand.Intn(1000)
	testName := fmt.Sprintf("test_%d", seq)
	dbfile, err := os.CreateTemp("", fmt.Sprintf("gorm-%s.db", testName))
	assert.NoError(t, err)
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + testName).AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &TestSqlProvider{Db: db}
	sqlStorage, err := storage.NewSqlStorage(provider, testName)
	assert.NoError(t, err)
	return dbfile, sqlStorage, db, testName
}
