package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGoStore(t *testing.T) {
	authSeconds := int64(1)
	aclSeconds := int64(1)
	store := NewGoStore(authSeconds, aclSeconds)

	ctx := context.Background()

	assert.Equal(t, authSeconds, store.authExpiration)
	assert.Equal(t, aclSeconds, store.aclExpiration)

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
	time.Sleep(1 * time.Second)

	present, granted = store.CheckAuthRecord(ctx, username, password)

	assert.False(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "true")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.True(t, granted)

	// Wait for it to expire.
	time.Sleep(1 * time.Second)

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
	time.Sleep(1 * time.Second)

	present, granted = store.CheckAuthRecord(ctx, username, password)

	assert.False(t, present)
	assert.False(t, granted)

	err = store.SetACLRecord(ctx, username, password, topic, acc, "false")
	assert.Nil(t, err)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.True(t, present)
	assert.False(t, granted)

	// Wait for it to expire.
	time.Sleep(1 * time.Second)

	present, granted = store.CheckACLRecord(ctx, username, password, topic, acc)

	assert.False(t, present)
	assert.False(t, granted)

}
