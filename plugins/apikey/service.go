package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/security/authorization"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

var apiKeyPrefixPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// NewService validates options and constructs the production API-key service.
func NewService(options Options) (*Service, error) {
	if options.Runtime.Adapter == nil {
		return nil, errors.New("apikey: Runtime.Adapter is required")
	}
	configurations, byID, defaultConfig, err := compileConfigurations(options.Configurations)
	if err != nil {
		return nil, err
	}
	clock := options.Runtime.Clock
	if clock == nil {
		clock = time.Now
	}
	keyGenerator := options.Runtime.KeyGenerator
	if keyGenerator == nil {
		reader := options.Runtime.Random
		keyGenerator = func(_ context.Context, length int, prefix string) (string, error) {
			return generateKey(reader, length, prefix)
		}
	}
	hasPlugin := options.Runtime.HasPlugin
	if hasPlugin == nil {
		hasPlugin = func(string) bool { return false }
	}
	organization := snapshotOrganizationAuthorization(options.Organization)
	if organization.CreatorRole == "" {
		organization.CreatorRole = "owner"
	}
	return &Service{
		options: options, configurations: configurations, byID: byID,
		defaultConfig: defaultConfig, adapter: options.Runtime.Adapter,
		clock: clock, keyGenerator: keyGenerator, hasPlugin: hasPlugin,
		organization: organization,
	}, nil
}

func compileConfigurations(input []Configuration) ([]Configuration, map[string]Configuration, Configuration, error) {
	if len(input) == 0 {
		input = []Configuration{{}}
	}
	compiled := make([]Configuration, len(input))
	byID := make(map[string]Configuration, len(input))
	defaultIndex := -1
	for index, raw := range input {
		config := raw
		if len(input) > 1 && strings.TrimSpace(config.ConfigID) == "" {
			return nil, nil, Configuration{}, errors.New("apikey: configId is required for each API key configuration")
		}
		config.ConfigID = normalizeConfigID(config.ConfigID)
		if _, exists := byID[config.ConfigID]; exists {
			return nil, nil, Configuration{}, fmt.Errorf("apikey: configId %q must be unique", config.ConfigID)
		}
		if config.References == "" {
			config.References = ReferenceUser
		}
		if config.References != ReferenceUser && config.References != ReferenceOrganization {
			return nil, nil, Configuration{}, fmt.Errorf("apikey: configuration %q has invalid references %q", config.ConfigID, config.References)
		}
		if config.DefaultKeyLength == 0 {
			config.DefaultKeyLength = 64
		}
		if config.DefaultKeyLength < 1 {
			return nil, nil, Configuration{}, fmt.Errorf("apikey: configuration %q has invalid key length", config.ConfigID)
		}
		if config.MinimumPrefixLength == 0 {
			config.MinimumPrefixLength = 1
		}
		if config.MaximumPrefixLength == 0 {
			config.MaximumPrefixLength = 32
		}
		if config.MinimumNameLength == 0 {
			config.MinimumNameLength = 1
		}
		if config.MaximumNameLength == 0 {
			config.MaximumNameLength = 32
		}
		if config.StartingCharactersLength == 0 {
			config.StartingCharactersLength = 6
		}
		if config.StoreStartingCharacters == nil {
			config.StoreStartingCharacters = Bool(true)
		}
		if config.RateLimitTimeWindow == 0 {
			config.RateLimitTimeWindow = 24 * time.Hour
		}
		if config.RateLimitMax == 0 {
			config.RateLimitMax = 10
		}
		if config.RateLimitEnabled == nil {
			config.RateLimitEnabled = Bool(true)
		}
		if config.MinimumExpiresIn == 0 {
			config.MinimumExpiresIn = 24 * time.Hour
		}
		if config.MaximumExpiresIn == 0 {
			config.MaximumExpiresIn = 365 * 24 * time.Hour
		}
		if config.MinimumExpiresIn < 0 || config.MaximumExpiresIn < config.MinimumExpiresIn {
			return nil, nil, Configuration{}, fmt.Errorf("apikey: configuration %q has invalid expiration limits", config.ConfigID)
		}
		config.DefaultPermissions = clonePermissions(config.DefaultPermissions)
		if len(config.APIKeyHeaders) == 0 {
			config.APIKeyHeaders = []string{"x-api-key"}
		} else {
			config.APIKeyHeaders = append([]string(nil), config.APIKeyHeaders...)
		}
		compiled[index] = config
		byID[config.ConfigID] = config
		if config.ConfigID == "default" {
			defaultIndex = index
		}
	}
	if defaultIndex < 0 {
		return compiled, byID, Configuration{}, nil
	}
	return compiled, byID, compiled[defaultIndex], nil
}

func snapshotOrganizationAuthorization(source OrganizationAuthorization) OrganizationAuthorization {
	result := OrganizationAuthorization{CreatorRole: source.CreatorRole}
	if source.Roles != nil {
		result.Roles = make(map[string]authorization.Statements, len(source.Roles))
		for roleName, statements := range source.Roles {
			cloned := make(authorization.Statements, len(statements))
			for resource, actions := range statements {
				cloned[resource] = append([]string(nil), actions...)
			}
			result.Roles[roleName] = cloned
		}
	}
	return result
}

func (service *Service) resolveConfiguration(configID string) (Configuration, error) {
	if strings.TrimSpace(configID) == "" {
		if service.defaultConfig.ConfigID == "" {
			return Configuration{}, apiError(contract.StatusBadRequest, ErrorNoDefaultAPIKeyConfigurationFound)
		}
		return service.defaultConfig, nil
	}
	config, exists := service.byID[normalizeConfigID(configID)]
	if !exists {
		return Configuration{}, apiError(contract.StatusBadRequest, ErrorNoDefaultAPIKeyConfigurationFound)
	}
	return config, nil
}

// Create mints and persists a user- or organization-owned API key.
func (service *Service) Create(ctx context.Context, input CreateInput) (APIKey, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	config, err := service.resolveConfiguration(input.ConfigID)
	if err != nil {
		return APIKey{}, err
	}
	actorUserID := input.ActorUserID
	var referenceID string
	if config.References == ReferenceOrganization {
		if strings.TrimSpace(input.OrganizationID) == "" {
			return APIKey{}, apiError(contract.StatusBadRequest, ErrorOrganizationIDRequired)
		}
		if actorUserID == "" {
			actorUserID = input.UserID
		}
		if actorUserID == "" {
			return APIKey{}, apiError(contract.StatusUnauthorized, ErrorUnauthorizedSession)
		}
		if err := service.authorizeOrganization(ctx, actorUserID, input.OrganizationID, PermissionCreate); err != nil {
			return APIKey{}, err
		}
		referenceID = input.OrganizationID
	} else {
		if actorUserID != "" && input.UserID != "" && actorUserID != input.UserID {
			return APIKey{}, apiError(contract.StatusUnauthorized, ErrorUnauthorizedSession)
		}
		referenceID = actorUserID
		if referenceID == "" {
			referenceID = input.UserID
		}
		if referenceID == "" {
			return APIKey{}, apiError(contract.StatusUnauthorized, ErrorUnauthorizedSession)
		}
	}

	prefix := input.Prefix
	if prefix == "" {
		prefix = config.DefaultPrefix
	}
	if input.Prefix != "" && (len(input.Prefix) < config.MinimumPrefixLength || len(input.Prefix) > config.MaximumPrefixLength) {
		return APIKey{}, apiError(contract.StatusBadRequest, ErrorInvalidPrefixLength)
	}
	if input.Prefix != "" && !apiKeyPrefixPattern.MatchString(input.Prefix) {
		return APIKey{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
	}
	if input.Name != nil {
		if len(*input.Name) < config.MinimumNameLength || len(*input.Name) > config.MaximumNameLength {
			return APIKey{}, apiError(contract.StatusBadRequest, ErrorInvalidNameLength)
		}
	} else if config.RequireName {
		return APIKey{}, apiError(contract.StatusBadRequest, ErrorNameRequired)
	}
	if input.ExpiresIn != nil && *input.ExpiresIn < time.Second {
		return APIKey{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
	}
	if input.Remaining != nil && *input.Remaining < 0 {
		return APIKey{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
	}
	if input.RefillAmount != nil && *input.RefillAmount < 1 {
		return APIKey{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
	}
	if (input.RefillAmount == nil) != (input.RefillInterval == nil) {
		if input.RefillAmount == nil {
			return APIKey{}, apiError(contract.StatusBadRequest, ErrorRefillIntervalAndAmountRequired)
		}
		return APIKey{}, apiError(contract.StatusBadRequest, ErrorRefillAmountAndIntervalRequired)
	}
	if input.ExpiresIn != nil {
		if config.DisableCustomExpiresTime {
			return APIKey{}, apiError(contract.StatusBadRequest, ErrorKeyDisabledExpiration)
		}
		if *input.ExpiresIn < config.MinimumExpiresIn {
			return APIKey{}, apiError(contract.StatusBadRequest, ErrorExpiresInTooSmall)
		}
		if *input.ExpiresIn > config.MaximumExpiresIn {
			return APIKey{}, apiError(contract.StatusBadRequest, ErrorExpiresInTooLarge)
		}
	}
	metadata, err := normalizeCreateMetadata(input.Metadata, config.EnableMetadata)
	if err != nil {
		return APIKey{}, err
	}

	plaintext, err := service.keyGenerator(ctx, config.DefaultKeyLength, prefix)
	if err != nil {
		return APIKey{}, err
	}
	storedKey := plaintext
	if !config.DisableKeyHashing {
		storedKey = HashKey(plaintext)
	}
	now := service.clock().UTC()
	var start any
	if config.StoreStartingCharacters != nil && *config.StoreStartingCharacters {
		characters := config.StartingCharactersLength
		if characters > len(plaintext) {
			characters = len(plaintext)
		}
		start = plaintext[:characters]
	}
	var expiresAt any
	if input.ExpiresIn != nil {
		expiresAt = now.Add(*input.ExpiresIn)
	} else if config.DefaultExpiresIn > 0 {
		expiresAt = now.Add(config.DefaultExpiresIn)
	}
	var refillInterval any
	if input.RefillInterval != nil {
		refillInterval = int64(*input.RefillInterval / time.Millisecond)
	}
	rateWindow := int64(config.RateLimitTimeWindow / time.Millisecond)
	if input.RateLimitTimeWindow != nil {
		rateWindow = int64(*input.RateLimitTimeWindow / time.Millisecond)
	}
	rateLimitMax := config.RateLimitMax
	if input.RateLimitMax != nil {
		rateLimitMax = *input.RateLimitMax
	}
	rateLimitEnabled := true
	if config.RateLimitEnabled != nil {
		rateLimitEnabled = *config.RateLimitEnabled
	}
	if input.RateLimitEnabled != nil {
		rateLimitEnabled = *input.RateLimitEnabled
	}
	permissions := input.Permissions
	if permissions == nil {
		permissions = config.DefaultPermissions
	}
	data := storage.Record{
		"configId": config.ConfigID, "name": nullableString(input.Name),
		"start": start, "prefix": nullableText(prefix), "key": storedKey,
		"referenceId": referenceID, "refillInterval": refillInterval,
		"refillAmount": nullableInt64(input.RefillAmount), "lastRefillAt": nil,
		"enabled": true, "rateLimitEnabled": rateLimitEnabled,
		"rateLimitTimeWindow": rateWindow, "rateLimitMax": rateLimitMax,
		"requestCount": int64(0), "remaining": nullableInt64(input.Remaining),
		"lastRequest": nil, "expiresAt": expiresAt, "createdAt": now,
		"updatedAt": now, "metadata": cloneJSONValue(metadata),
		"permissions": clonePermissions(permissions),
	}
	created, err := service.adapter.Create(ctx, storage.CreateParams{Model: "apikey", Data: data})
	if err != nil {
		return APIKey{}, fmt.Errorf("apikey: create: %w", err)
	}
	result := apiKeyFromRecord(created)
	result.Key = plaintext
	return result, nil
}

// Get returns one key after configuration, ownership, and organization ACL checks.
func (service *Service) Get(ctx context.Context, input GetInput) (APIKey, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	lookupConfig, err := service.resolveConfiguration(input.ConfigID)
	if err != nil {
		return APIKey{}, err
	}
	record, err := service.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "apikey", Where: []storage.Where{{Field: "id", Value: input.ID}},
	})
	if err != nil {
		return APIKey{}, err
	}
	if record == nil {
		return APIKey{}, apiError(contract.StatusNotFound, ErrorKeyNotFound)
	}
	key := apiKeyFromRecord(record)
	if normalizeConfigID(key.ConfigID) != normalizeConfigID(lookupConfig.ConfigID) {
		return APIKey{}, apiError(contract.StatusNotFound, ErrorKeyNotFound)
	}
	config, exists := service.byID[normalizeConfigID(key.ConfigID)]
	if !exists {
		return APIKey{}, apiError(contract.StatusNotFound, ErrorKeyNotFound)
	}
	if config.References == ReferenceOrganization {
		if err := service.authorizeOrganization(ctx, input.ActorUserID, key.ReferenceID, PermissionRead); err != nil {
			return APIKey{}, err
		}
	} else if key.ReferenceID != input.ActorUserID {
		return APIKey{}, apiError(contract.StatusNotFound, ErrorKeyNotFound)
	}
	return withoutSecret(key), nil
}

// List returns only user keys or only organization keys depending on whether
// OrganizationID is present, matching single-auth's ownership separation.
func (service *Service) List(ctx context.Context, input ListInput) (ListResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if input.ActorUserID == "" {
		return ListResult{}, apiError(contract.StatusUnauthorized, ErrorUnauthorizedSession)
	}
	referenceID := input.ActorUserID
	expectedType := ReferenceUser
	if input.OrganizationID != "" {
		if err := service.authorizeOrganization(ctx, input.ActorUserID, input.OrganizationID, PermissionRead); err != nil {
			return ListResult{}, err
		}
		referenceID = input.OrganizationID
		expectedType = ReferenceOrganization
	}
	if input.ConfigID != "" {
		if _, err := service.resolveConfiguration(input.ConfigID); err != nil {
			return ListResult{}, err
		}
	}
	rows, err := service.adapter.FindMany(ctx, storage.FindManyParams{
		Model: "apikey", Where: []storage.Where{{Field: "referenceId", Value: referenceID}},
	})
	if err != nil {
		return ListResult{}, err
	}
	keys := make([]APIKey, 0, len(rows))
	for _, row := range rows {
		key := apiKeyFromRecord(row)
		config, exists := service.byID[normalizeConfigID(key.ConfigID)]
		if !exists || config.References != expectedType || key.ReferenceID != referenceID {
			continue
		}
		if input.ConfigID != "" && normalizeConfigID(key.ConfigID) != normalizeConfigID(input.ConfigID) {
			continue
		}
		keys = append(keys, withoutSecret(key))
	}
	total := len(keys)
	if input.Offset != nil {
		if *input.Offset >= len(keys) {
			keys = nil
		} else if *input.Offset > 0 {
			keys = keys[*input.Offset:]
		}
	}
	if input.Limit != nil && *input.Limit >= 0 && *input.Limit < len(keys) {
		keys = keys[:*input.Limit]
	}
	return ListResult{APIKeys: keys, Total: total, Limit: input.Limit, Offset: input.Offset}, nil
}

// Update changes an API key after ownership and update-permission checks.
func (service *Service) Update(ctx context.Context, input UpdateInput) (APIKey, error) {
	return service.update(ctx, input, false)
}

func (service *Service) update(ctx context.Context, input UpdateInput, expiresInExceedsDuration bool) (APIKey, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	lookupConfig, err := service.resolveConfiguration(input.ConfigID)
	if err != nil {
		return APIKey{}, err
	}
	record, err := service.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "apikey", Where: []storage.Where{{Field: "id", Value: input.KeyID}},
	})
	if err != nil {
		return APIKey{}, err
	}
	if record == nil {
		return APIKey{}, apiError(contract.StatusNotFound, ErrorKeyNotFound)
	}
	key := apiKeyFromRecord(record)
	if normalizeConfigID(key.ConfigID) != normalizeConfigID(lookupConfig.ConfigID) {
		return APIKey{}, apiError(contract.StatusNotFound, ErrorKeyNotFound)
	}
	config := service.byID[normalizeConfigID(key.ConfigID)]
	if config.References == ReferenceOrganization {
		if err := service.authorizeOrganization(ctx, input.ActorUserID, key.ReferenceID, PermissionUpdate); err != nil {
			return APIKey{}, err
		}
	} else if key.ReferenceID != input.ActorUserID {
		return APIKey{}, apiError(contract.StatusNotFound, ErrorKeyNotFound)
	}
	update := storage.Record{}
	if input.Name != nil {
		if len(*input.Name) < config.MinimumNameLength || len(*input.Name) > config.MaximumNameLength {
			return APIKey{}, apiError(contract.StatusBadRequest, ErrorInvalidNameLength)
		}
		update["name"] = *input.Name
	}
	if input.Enabled != nil {
		update["enabled"] = *input.Enabled
	}
	if input.ExpiresInSet {
		if config.DisableCustomExpiresTime {
			return APIKey{}, apiError(contract.StatusBadRequest, ErrorKeyDisabledExpiration)
		}
		if input.ExpiresIn == nil {
			update["expiresAt"] = nil
		} else {
			if expiresInExceedsDuration {
				return APIKey{}, apiError(contract.StatusBadRequest, ErrorExpiresInTooLarge)
			}
			if *input.ExpiresIn < time.Second {
				return APIKey{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
			}
			if *input.ExpiresIn < config.MinimumExpiresIn {
				return APIKey{}, apiError(contract.StatusBadRequest, ErrorExpiresInTooSmall)
			}
			if *input.ExpiresIn > config.MaximumExpiresIn {
				return APIKey{}, apiError(contract.StatusBadRequest, ErrorExpiresInTooLarge)
			}
			update["expiresAt"] = service.clock().UTC().Add(*input.ExpiresIn)
		}
	}
	if input.MetadataSet && config.EnableMetadata {
		metadata, metadataErr := normalizeUpdateMetadata(input.Metadata)
		if metadataErr != nil {
			return APIKey{}, metadataErr
		}
		update["metadata"] = cloneJSONValue(metadata)
	}
	if input.Remaining != nil {
		if *input.Remaining < 1 {
			return APIKey{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		}
		update["remaining"] = *input.Remaining
	}
	if input.RefillAmount != nil || input.RefillInterval != nil {
		if input.RefillAmount == nil {
			return APIKey{}, apiError(contract.StatusBadRequest, ErrorRefillIntervalAndAmountRequired)
		}
		if input.RefillInterval == nil {
			return APIKey{}, apiError(contract.StatusBadRequest, ErrorRefillAmountAndIntervalRequired)
		}
		update["refillAmount"] = *input.RefillAmount
		update["refillInterval"] = int64(*input.RefillInterval / time.Millisecond)
	}
	if input.RateLimitEnabled != nil {
		update["rateLimitEnabled"] = *input.RateLimitEnabled
	}
	if input.RateLimitTimeWindow != nil {
		update["rateLimitTimeWindow"] = int64(*input.RateLimitTimeWindow / time.Millisecond)
	}
	if input.RateLimitMax != nil {
		update["rateLimitMax"] = *input.RateLimitMax
	}
	if input.PermissionsSet {
		update["permissions"] = clonePermissions(input.Permissions)
	}
	if len(update) == 0 {
		return APIKey{}, apiError(contract.StatusBadRequest, ErrorNoValuesToUpdate)
	}
	update["updatedAt"] = service.clock().UTC()
	updated, err := service.adapter.Update(ctx, storage.UpdateParams{
		Model: "apikey", Where: []storage.Where{{Field: "id", Value: input.KeyID}}, Update: update,
	})
	if err != nil {
		return APIKey{}, err
	}
	return withoutSecret(apiKeyFromRecord(updated)), nil
}

// Delete removes an API key after ownership and delete-permission checks.
func (service *Service) Delete(ctx context.Context, input DeleteInput) error {
	if ctx == nil {
		ctx = context.Background()
	}
	lookupConfig, err := service.resolveConfiguration(input.ConfigID)
	if err != nil {
		return err
	}
	record, err := service.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "apikey", Where: []storage.Where{{Field: "id", Value: input.KeyID}},
	})
	if err != nil {
		return err
	}
	if record == nil {
		return apiError(contract.StatusNotFound, ErrorKeyNotFound)
	}
	key := apiKeyFromRecord(record)
	if normalizeConfigID(key.ConfigID) != normalizeConfigID(lookupConfig.ConfigID) {
		return apiError(contract.StatusNotFound, ErrorKeyNotFound)
	}
	config := service.byID[normalizeConfigID(key.ConfigID)]
	if config.References == ReferenceOrganization {
		if err := service.authorizeOrganization(ctx, input.ActorUserID, key.ReferenceID, PermissionDelete); err != nil {
			return err
		}
	} else if key.ReferenceID != input.ActorUserID {
		return apiError(contract.StatusNotFound, ErrorKeyNotFound)
	}
	return service.adapter.Delete(ctx, storage.DeleteParams{
		Model: "apikey", Where: []storage.Where{{Field: "id", Value: input.KeyID}},
	})
}

// Verify validates a plaintext credential and returns its owner/configuration
// metadata without disclosing the stored hash.
func (service *Service) Verify(ctx context.Context, input VerifyInput) VerifyResult {
	if ctx == nil {
		ctx = context.Background()
	}
	configs := service.configurations
	if input.ConfigID != "" {
		config, err := service.resolveConfiguration(input.ConfigID)
		if err != nil {
			return verifyFailure(err)
		}
		configs = []Configuration{config}
	}
	for _, config := range configs {
		lookup := input.Key
		if !config.DisableKeyHashing {
			lookup = HashKey(input.Key)
		}
		record, err := service.adapter.FindOne(ctx, storage.FindOneParams{
			Model: "apikey", Where: []storage.Where{
				{Field: "key", Value: lookup},
				{Field: "configId", Value: config.ConfigID},
			},
		})
		if err != nil {
			return verifyFailure(err)
		}
		if record == nil {
			continue
		}
		key := apiKeyFromRecord(record)
		if !key.Enabled {
			return verifyFailure(apiError(contract.StatusUnauthorized, ErrorKeyDisabled))
		}
		now := service.clock().UTC()
		if key.ExpiresAt != nil && now.After(*key.ExpiresAt) {
			if deleteErr := service.adapter.Delete(ctx, storage.DeleteParams{
				Model: "apikey", Where: []storage.Where{{Field: "id", Value: key.ID}},
			}); deleteErr != nil {
				return verifyFailure(deleteErr)
			}
			return verifyFailure(apiError(contract.StatusUnauthorized, ErrorKeyExpired))
		}
		if len(input.Permissions) > 0 {
			if len(key.Permissions) == 0 || !apiKeyPermissionsAuthorize(key.Permissions, input.Permissions) {
				return verifyFailure(apiError(contract.StatusUnauthorized, ErrorKeyNotFound))
			}
		}
		if key.Remaining != nil && *key.Remaining == 0 && key.RefillAmount == nil {
			if deleteErr := service.adapter.Delete(ctx, storage.DeleteParams{
				Model: "apikey", Where: []storage.Where{{Field: "id", Value: key.ID}},
			}); deleteErr != nil {
				return verifyFailure(deleteErr)
			}
			return verifyFailure(apiError(contract.StatusTooManyRequests, ErrorUsageExceeded))
		}
		if key.Remaining != nil {
			claimed, claimErr := service.claimRemaining(ctx, key, now)
			if claimErr != nil {
				return verifyFailure(claimErr)
			}
			key = claimed
		}
		claimed, claimErr := service.claimRateLimit(ctx, key, config, now)
		if claimErr != nil {
			return verifyFailure(claimErr)
		}
		key = claimed
		updated, updateErr := service.adapter.Update(ctx, storage.UpdateParams{
			Model: "apikey", Where: []storage.Where{{Field: "id", Value: key.ID}},
			Update: storage.Record{"updatedAt": now},
		})
		if updateErr != nil {
			return verifyFailure(updateErr)
		}
		if updated == nil {
			return verifyFailure(apiError(contract.StatusUnauthorized, ErrorInvalidAPIKey))
		}
		result := withoutSecret(apiKeyFromRecord(updated))
		return VerifyResult{Valid: true, Key: &result}
	}
	return verifyFailure(apiError(contract.StatusUnauthorized, ErrorInvalidAPIKey))
}

func (service *Service) claimRemaining(ctx context.Context, key APIKey, now time.Time) (APIKey, error) {
	if key.Remaining == nil {
		return key, nil
	}
	if key.RefillInterval != nil && key.RefillAmount != nil && *key.RefillInterval > 0 && *key.RefillAmount > 0 {
		lastRefill := key.CreatedAt
		var observedLastRefill any
		if key.LastRefillAt != nil {
			lastRefill = *key.LastRefillAt
			observedLastRefill = *key.LastRefillAt
		}
		if now.Sub(lastRefill) > time.Duration(*key.RefillInterval)*time.Millisecond {
			refilled, err := service.adapter.IncrementOne(ctx, storage.IncrementOneParams{
				Model: "apikey",
				Where: []storage.Where{
					{Field: "id", Value: key.ID},
					{Field: "lastRefillAt", Value: observedLastRefill},
				},
				Set: storage.Record{"remaining": *key.RefillAmount - 1, "lastRefillAt": now},
			})
			if err != nil {
				return APIKey{}, err
			}
			if refilled != nil {
				return apiKeyFromRecord(refilled), nil
			}
		}
	}
	decremented, err := service.adapter.IncrementOne(ctx, storage.IncrementOneParams{
		Model: "apikey",
		Where: []storage.Where{
			{Field: "id", Value: key.ID},
			{Field: "remaining", Operator: storage.OpGt, Value: int64(0)},
		},
		Increment: map[string]float64{"remaining": -1},
	})
	if err != nil {
		return APIKey{}, err
	}
	if decremented == nil {
		return APIKey{}, apiError(contract.StatusTooManyRequests, ErrorUsageExceeded)
	}
	return apiKeyFromRecord(decremented), nil
}

func (service *Service) claimRateLimit(
	ctx context.Context,
	key APIKey,
	config Configuration,
	now time.Time,
) (APIKey, error) {
	if config.RateLimitEnabled != nil && !*config.RateLimitEnabled || !key.RateLimitEnabled {
		updated, err := service.adapter.Update(ctx, storage.UpdateParams{
			Model: "apikey", Where: []storage.Where{{Field: "id", Value: key.ID}},
			Update: storage.Record{"lastRequest": now},
		})
		if err != nil {
			return APIKey{}, err
		}
		if updated == nil {
			return APIKey{}, apiError(contract.StatusUnauthorized, ErrorInvalidAPIKey)
		}
		return apiKeyFromRecord(updated), nil
	}
	if key.RateLimitTimeWindow == nil || key.RateLimitMax == nil {
		return key, nil
	}
	window := time.Duration(*key.RateLimitTimeWindow) * time.Millisecond
	if key.LastRequest == nil {
		started, err := service.adapter.IncrementOne(ctx, storage.IncrementOneParams{
			Model: "apikey",
			Where: []storage.Where{
				{Field: "id", Value: key.ID},
				{Field: "lastRequest", Value: nil},
			},
			Set: storage.Record{"requestCount": int64(1), "lastRequest": now},
		})
		if err != nil {
			return APIKey{}, err
		}
		if started != nil {
			return apiKeyFromRecord(started), nil
		}
		return service.reloadAndClaimRateLimit(ctx, key.ID, config, now)
	}
	windowStart := now.Add(-window)
	if now.Sub(*key.LastRequest) > window {
		reset, err := service.adapter.IncrementOne(ctx, storage.IncrementOneParams{
			Model: "apikey",
			Where: []storage.Where{
				{Field: "id", Value: key.ID},
				{Field: "lastRequest", Operator: storage.OpLTE, Value: windowStart},
			},
			Set: storage.Record{"requestCount": int64(1), "lastRequest": now},
		})
		if err != nil {
			return APIKey{}, err
		}
		if reset != nil {
			return apiKeyFromRecord(reset), nil
		}
		return service.reloadAndClaimRateLimit(ctx, key.ID, config, now)
	}
	if key.RequestCount >= *key.RateLimitMax {
		return APIKey{}, apiError(contract.StatusTooManyRequests, ErrorRateLimited)
	}
	incremented, err := service.adapter.IncrementOne(ctx, storage.IncrementOneParams{
		Model: "apikey",
		Where: []storage.Where{
			{Field: "id", Value: key.ID},
			{Field: "lastRequest", Operator: storage.OpGt, Value: windowStart},
			{Field: "requestCount", Operator: storage.OpLt, Value: *key.RateLimitMax},
		},
		Increment: map[string]float64{"requestCount": 1},
		Set:       storage.Record{"lastRequest": now},
	})
	if err != nil {
		return APIKey{}, err
	}
	if incremented != nil {
		return apiKeyFromRecord(incremented), nil
	}
	return service.reloadAndClaimRateLimit(ctx, key.ID, config, now)
}

func (service *Service) reloadAndClaimRateLimit(
	ctx context.Context,
	keyID string,
	config Configuration,
	now time.Time,
) (APIKey, error) {
	record, err := service.adapter.FindOne(ctx, storage.FindOneParams{
		Model: "apikey", Where: []storage.Where{{Field: "id", Value: keyID}},
	})
	if err != nil {
		return APIKey{}, err
	}
	if record == nil {
		return APIKey{}, apiError(contract.StatusUnauthorized, ErrorInvalidAPIKey)
	}
	return service.claimRateLimit(ctx, apiKeyFromRecord(record), config, now)
}

func apiKeyPermissionsAuthorize(granted, requested map[string][]string) bool {
	request := make(authorization.AuthorizeRequest, 0, len(requested))
	resources := make([]string, 0, len(requested))
	for resource := range requested {
		resources = append(resources, resource)
	}
	sort.Strings(resources)
	for _, resource := range resources {
		request = append(request, authorization.ResourceRequest{Resource: resource, Actions: requested[resource]})
	}
	result, err := authorization.NewRole(authorization.Statements(granted)).Authorize(request)
	return err == nil && result.Success
}

func verifyFailure(err error) VerifyResult {
	statusError, ok := contract.AsAPIError(err)
	if !ok {
		return VerifyResult{Error: &ErrorBody{Message: errorMessages[ErrorInvalidAPIKey], Code: ErrorInvalidAPIKey}}
	}
	return VerifyResult{Error: &ErrorBody{Message: statusError.Message, Code: statusError.Code}}
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func normalizeCreateMetadata(source any, enabled bool) (any, error) {
	if source == nil {
		return nil, nil
	}
	normalized, ok := metadataObject(source)
	if !ok {
		return nil, apiError(contract.StatusBadRequest, ErrorInvalidMetadataType)
	}
	if !enabled {
		return nil, apiError(contract.StatusBadRequest, ErrorMetadataDisabled)
	}
	return normalized, nil
}

func normalizeUpdateMetadata(source any) (any, error) {
	if source == nil {
		return nil, nil
	}
	normalized, ok := metadataObject(source)
	if !ok {
		return nil, apiError(contract.StatusBadRequest, ErrorInvalidMetadataType)
	}
	return normalized, nil
}

func metadataObject(source any) (any, bool) {
	switch typed := source.(type) {
	case map[string]any, []any:
		return cloneJSONValue(typed), true
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		return nil, false
	}
	var decoded any
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, false
	}
	switch decoded.(type) {
	case map[string]any, []any:
		return cloneJSONValue(decoded), true
	default:
		return nil, false
	}
}

func cloneJSONValue(source any) any {
	switch typed := source.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, value := range typed {
			result[key] = cloneJSONValue(value)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, value := range typed {
			result[index] = cloneJSONValue(value)
		}
		return result
	default:
		return typed
	}
}

func clonePermissions(source map[string][]string) map[string][]string {
	if source == nil {
		return nil
	}
	result := make(map[string][]string, len(source))
	for resource, actions := range source {
		result[resource] = append([]string(nil), actions...)
	}
	return result
}
