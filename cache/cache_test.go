package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGoStore(t *testing.T) {
	authExpiration := 100 * time.Millisecond
	aclExpiration := 100 * time.Millisecond
	store := NewGoStore(authExpiration, aclExpiration)

	ctx := context.Background()

	assert.Equal(t, authExpiration, store.authExpiration)
	assert.Equal(t, aclExpiration, store.aclExpiration)

	assert.True(t, store.Connect(ctx, false))

	username := "test-user"
	password := "test-password"
	topic := "test/topic"
	acc := 1

	// Test granted access.
	err := store.SetAuthRecord(ctx, username, password, "true")
	assert.Nil(t, err)

	present, granted := store.CheckAuthRecord(ctx, username, password)

	assert.True(t, present)
	assert.True(t, granted)

	// Wait for it to expire.
	time.Sleep(150 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password)

	assert.False(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "true")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.True(t, granted)

	// Wait for it to expire.
	time.Sleep(150 * time.Millisecond)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.False(t, present)
	assert.False(t, granted)

	// Test not granted access.
	err = store.SetAuthRecord(ctx, username, password, "false")
	assert.Nil(t, err)

	present, granted = store.CheckAuthRecord(ctx, username, password)

	assert.True(t, present)
	assert.False(t, granted)

	// Wait for it to expire.
	time.Sleep(150 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password)

	assert.False(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "false")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.False(t, granted)

	// Wait for it to expire.
	time.Sleep(150 * time.Millisecond)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.False(t, present)
	assert.False(t, granted)

}

func TestRedisSingleStore(t *testing.T) {
	authExpiration := 1000 * time.Millisecond
	aclExpiration := 1000 * time.Millisecond
	store := NewSingleRedisStore("localhost", "6379", "", 3, authExpiration, aclExpiration)

	ctx := context.Background()

	assert.Equal(t, authExpiration, store.authExpiration)
	assert.Equal(t, aclExpiration, store.aclExpiration)

	assert.True(t, store.Connect(ctx, false))

	username := "test-user"
	password := "test-password"
	topic := "test/topic"
	acc := 1

	// Test granted access.
	err := store.SetAuthRecord(ctx, username, password, "true")
	assert.Nil(t, err)

	present, granted := store.CheckAuthRecord(ctx, username, password)

	assert.True(t, present)
	assert.True(t, granted)

	// Wait for it to expire. For Redis we do this just once since the package used (or Redis itself, not sure) doesn't
	// support less than 1s expiration times: "specified duration is 100ms, but minimal supported value is 1s"
	time.Sleep(1050 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password)

	assert.False(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "true")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.True(t, granted)

	// Test not granted access.
	err = store.SetAuthRecord(ctx, username, password, "false")
	assert.Nil(t, err)

	present, granted = store.CheckAuthRecord(ctx, username, password)

	assert.True(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "false")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.False(t, granted)
}

func TestRedisClusterStore(t *testing.T) {
	authExpiration := 1000 * time.Millisecond
	aclExpiration := 1000 * time.Millisecond

	addresses := []string{"localhost:7000", "localhost:7001", "localhost:7002"}
	store := NewRedisClusterStore("", addresses, authExpiration, aclExpiration)

	ctx := context.Background()

	assert.Equal(t, authExpiration, store.authExpiration)
	assert.Equal(t, aclExpiration, store.aclExpiration)

	assert.True(t, store.Connect(ctx, false))

	username := "test-user"
	password := "test-password"
	topic := "test/topic"
	acc := 1

	// Test granted access.
	err := store.SetAuthRecord(ctx, username, password, "true")
	assert.Nil(t, err)

	present, granted := store.CheckAuthRecord(ctx, username, password)

	assert.True(t, present)
	assert.True(t, granted)

	// Wait for it to expire. For Redis we do this just once since the package used (or Redis itself, not sure) doesn't
	// support less than 1s expiration times: "specified duration is 100ms, but minimal supported value is 1s"
	time.Sleep(1050 * time.Millisecond)

	present, granted = store.CheckAuthRecord(ctx, username, password)

	assert.False(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "true")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.True(t, granted)

	// Test not granted access.
	err = store.SetAuthRecord(ctx, username, password, "false")
	assert.Nil(t, err)

	present, granted = store.CheckAuthRecord(ctx, username, password)

	assert.True(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "false")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.False(t, granted)
}
