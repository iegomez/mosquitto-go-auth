package cache

import (
	"context"
	"crypto/sha1"
	b64 "encoding/base64"
	"fmt"
	"hash"
	"math/rand"
	"strings"
	"time"

	goredis "github.com/go-redis/redis/v8"
	bes "github.com/iegomez/mosquitto-go-auth/backends"
	goCache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

// redisCache stores necessary values for Redis cache
type redisStore struct {
	client  bes.RedisClient
	h       hash.Hash
	options Options
}

type goStore struct {
	client  *goCache.Cache
	h       hash.Hash
	options Options
}

type Options struct {
	AuthExpiration      time.Duration
	AclExpiration       time.Duration
	SuperuserExpiration time.Duration
	AuthJitter          time.Duration
	AclJitter           time.Duration
	SuperuserJitter     time.Duration
	RefreshExpiration   bool
}

const (
	defaultExpiration = 30
)

type Store interface {
	SetAuthRecord(ctx context.Context, username, password, granted string) error
	CheckAuthRecord(ctx context.Context, username, password string) (bool, bool)
	SetACLRecord(ctx context.Context, username, topic, clientid string, acc int, granted string) error
	CheckACLRecord(ctx context.Context, username, topic, clientid string, acc int) (bool, bool)
	SetSuperuserRecord(ctx context.Context, username, password, granted string) error
	CheckSuperuserRecord(ctx context.Context, username, password string) (bool, bool)
	Connect(ctx context.Context, reset bool) bool
	Close()
}

// NewGoStore initializes a cache using go-cache as the store.
func NewGoStore(options Options) *goStore {
	// TODO: support hydrating the cache to retain previous values.

	return &goStore{
		client:  goCache.New(time.Second*defaultExpiration, time.Second*(defaultExpiration*2)),
		h:       sha1.New(),
		options: options,
	}
}

// NewSingleRedisStore initializes a cache using a single Redis instance as the store.
func NewSingleRedisStore(host, port, password string, db int, options Options) *redisStore {
	addr := fmt.Sprintf("%s:%s", host, port)
	redisClient := goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return &redisStore{
		client:  bes.SingleRedisClient{redisClient},
		h:       sha1.New(),
		options: options,
	}
}

// NewSingleRedisStore initializes a cache using a Redis Cluster as the store.
func NewRedisClusterStore(password string, addresses []string, options Options) *redisStore {
	clusterClient := goredis.NewClusterClient(
		&goredis.ClusterOptions{
			Addrs:    addresses,
			Password: password,
		})

	return &redisStore{
		client:  clusterClient,
		h:       sha1.New(),
		options: options,
	}
}

func toAuthRecord(username, password string, h hash.Hash) string {
	sum := h.Sum([]byte(fmt.Sprintf("auth-%s-%s", username, password)))
	log.Debugf("to auth record: %v\n", sum)
	return b64.StdEncoding.EncodeToString(sum)
}

func toSuperuserRecord(username, password string, h hash.Hash) string {
	sum := h.Sum([]byte(fmt.Sprintf("superuser-%s-%s", username, password)))
	log.Debugf("to superuser record: %v\n", sum)
	return b64.StdEncoding.EncodeToString(sum)
}

func toACLRecord(username, topic, clientid string, acc int, h hash.Hash) string {
	sum := h.Sum([]byte(fmt.Sprintf("acl-%s-%s-%s-%d", username, topic, clientid, acc)))
	log.Debugf("to acl record: %v\n", sum)
	return b64.StdEncoding.EncodeToString(sum)
}

// Checks if an error was caused by a moved record in a Redis Cluster.
func isMovedError(err error) bool {
	s := err.Error()
	if strings.HasPrefix(s, "MOVED ") || strings.HasPrefix(s, "ASK ") {
		return true
	}

	return false
}

// Return an expiration duration with a jitter added, i.e the actual expiration is in the range [expiration - jitter, expiration + jitter].
// If no expiration was set or jitter > expiration, then any negative value will yield 0 instead.
func expirationWithJitter(expiration, jitter time.Duration) time.Duration {
	if jitter == 0 {
		return expiration
	}

	result := expiration + time.Duration(rand.Int63n(int64(jitter)*2)-int64(jitter))
	if result < 0 {
		return 0
	}

	return result
}

// Connect flushes the cache if reset is set.
func (s *goStore) Connect(ctx context.Context, reset bool) bool {
	log.Infoln("started go-cache")
	if reset {
		s.client.Flush()
		log.Infoln("flushed go-cache")
	}
	return true
}

// Connect pings Redis and flushes the cache if reset is set.
func (s *redisStore) Connect(ctx context.Context, reset bool) bool {
	_, err := s.client.Ping(ctx).Result()
	if err != nil {
		log.Errorf("couldn't start redis. error: %s", err)
		return false
	} else {
		log.Infoln("started redis cache")
		//Check if cache must be reset
		if reset {
			s.client.FlushDB(ctx)
			log.Infoln("flushed redis cache")
		}
	}
	return true
}

func (s *goStore) Close() {
	//TODO: support serializing cache for re hydration.
}

func (s *redisStore) Close() {
	s.client.Close()
}

// CheckAuthRecord checks if the username/password pair is present in the cache. Return if it's present and, if so, if it was granted privileges
func (s *goStore) CheckAuthRecord(ctx context.Context, username, password string) (bool, bool) {
	record := toAuthRecord(username, password, s.h)
	return s.checkRecord(ctx, record, expirationWithJitter(s.options.AuthExpiration, s.options.AuthJitter))
}

// CheckAclRecord checks if the username/topic/clientid/acc mix is present in the cache. Return if it's present and, if so, if it was granted privileges.
func (s *goStore) CheckACLRecord(ctx context.Context, username, topic, clientid string, acc int) (bool, bool) {
	record := toACLRecord(username, topic, clientid, acc, s.h)
	return s.checkRecord(ctx, record, expirationWithJitter(s.options.AclExpiration, s.options.AclJitter))
}

// CheckSuperuserRecord checks if the username is in the superuser cache. Return if it's present and, if so, if it was granted privileges.
func (s *goStore) CheckSuperuserRecord(ctx context.Context, username, password string) (bool, bool) {
	record := toSuperuserRecord(username, password, s.h)
	return s.checkRecord(ctx, record, expirationWithJitter(s.options.SuperuserExpiration, s.options.SuperuserJitter))
}

func (s *goStore) checkRecord(ctx context.Context, record string, expirationTime time.Duration) (bool, bool) {
	granted := false
	v, present := s.client.Get(record)

	if present {
		value, ok := v.(string)
		if ok && value == "true" {
			granted = true
		}

		if s.options.RefreshExpiration {
			s.client.Set(record, value, expirationTime)
		}
	}
	return present, granted
}

// CheckAuthRecord checks if the username/password pair is present in the cache. Return if it's present and, if so, if it was granted privileges
func (s *redisStore) CheckAuthRecord(ctx context.Context, username, password string) (bool, bool) {
	record := toAuthRecord(username, password, s.h)
	return s.checkRecord(ctx, record, expirationWithJitter(s.options.AuthExpiration, s.options.AuthJitter))
}

// CheckAclRecord checks if the username/topic/clientid/acc mix is present in the cache. Return if it's present and, if so, if it was granted privileges.
func (s *redisStore) CheckACLRecord(ctx context.Context, username, topic, clientid string, acc int) (bool, bool) {
	record := toACLRecord(username, topic, clientid, acc, s.h)
	return s.checkRecord(ctx, record, expirationWithJitter(s.options.AclExpiration, s.options.AclJitter))
}

// CheckSuperuserRecord checks if the username is in the superuser cache. Return if it's present and, if so, if it was granted privileges.
func (s *redisStore) CheckSuperuserRecord(ctx context.Context, username, password string) (bool, bool) {
	record := toSuperuserRecord(username, password, s.h)
	return s.checkRecord(ctx, record, expirationWithJitter(s.options.SuperuserExpiration, s.options.SuperuserJitter))
}

func (s *redisStore) checkRecord(ctx context.Context, record string, expirationTime time.Duration) (bool, bool) {

	present, granted, err := s.getAndRefresh(ctx, record, expirationTime)
	if err == nil {
		return present, granted
	}

	if isMovedError(err) {
		s.client.ReloadState(ctx)

		//Retry once.
		present, granted, err = s.getAndRefresh(ctx, record, expirationTime)
	}

	if err != nil {
		log.Debugf("set cache error: %s", err)
	}

	return present, granted
}

func (s *redisStore) getAndRefresh(ctx context.Context, record string, expirationTime time.Duration) (bool, bool, error) {
	val, err := s.client.Get(ctx, record).Result()
	if err != nil {
		return false, false, err
	}

	if s.options.RefreshExpiration {
		_, err = s.client.Expire(ctx, record, expirationTime).Result()
		if err != nil {
			return false, false, err
		}
	}

	if val == "true" {
		return true, true, nil
	}

	return true, false, nil
}

// SetAuthRecord sets a pair, granted option and expiration time.
func (s *goStore) SetAuthRecord(ctx context.Context, username, password string, granted string) error {
	record := toAuthRecord(username, password, s.h)
	s.client.Set(record, granted, expirationWithJitter(s.options.AuthExpiration, s.options.AuthJitter))

	return nil
}

// SetAclRecord sets a mix, granted option and expiration time.
func (s *goStore) SetACLRecord(ctx context.Context, username, topic, clientid string, acc int, granted string) error {
	record := toACLRecord(username, topic, clientid, acc, s.h)
	s.client.Set(record, granted, expirationWithJitter(s.options.AclExpiration, s.options.AclJitter))

	return nil
}

// SetSuperuserRecord sets a pair, granted option and expiration time.
func (s *goStore) SetSuperuserRecord(ctx context.Context, username, password string, granted string) error {
	record := toSuperuserRecord(username, password, s.h)
	s.client.Set(record, granted, expirationWithJitter(s.options.AuthExpiration, s.options.AuthJitter))

	return nil
}

// SetAuthRecord sets a pair, granted option and expiration time.
func (s *redisStore) SetAuthRecord(ctx context.Context, username, password string, granted string) error {
	record := toAuthRecord(username, password, s.h)
	return s.setRecord(ctx, record, granted, expirationWithJitter(s.options.AuthExpiration, s.options.AuthJitter))
}

// SetAclRecord sets a mix, granted option and expiration time.
func (s *redisStore) SetACLRecord(ctx context.Context, username, topic, clientid string, acc int, granted string) error {
	record := toACLRecord(username, topic, clientid, acc, s.h)
	return s.setRecord(ctx, record, granted, expirationWithJitter(s.options.AclExpiration, s.options.AclJitter))
}

// SetSuperuserRecord sets a pair, granted option and expiration time.
func (s *redisStore) SetSuperuserRecord(ctx context.Context, username, password string, granted string) error {
	record := toSuperuserRecord(username, password, s.h)
	return s.setRecord(ctx, record, granted, expirationWithJitter(s.options.AuthExpiration, s.options.AuthJitter))
}

func (s *redisStore) setRecord(ctx context.Context, record, granted string, expirationTime time.Duration) error {
	err := s.set(ctx, record, granted, expirationTime)

	if err == nil {
		return nil
	}

	// If record was moved, reload and retry.
	if isMovedError(err) {
		s.client.ReloadState(ctx)

		//Retry once.
		err = s.set(ctx, record, granted, expirationTime)
	}

	return err
}

func (s *redisStore) set(ctx context.Context, record string, granted string, expirationTime time.Duration) error {
	return s.client.Set(ctx, record, granted, expirationTime).Err()
}
