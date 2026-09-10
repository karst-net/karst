package http

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain/manager"

	"github.com/netbirdio/netbird/management/server/types"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxytoken"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	reverseproxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service/manager"

	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	idpmanager "github.com/netbirdio/netbird/management/server/idp"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agentnetworkhandlers "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/handlers"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	zonesManager "github.com/netbirdio/netbird/management/internals/modules/zones/manager"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	recordsManager "github.com/netbirdio/netbird/management/internals/modules/zones/records/manager"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/settings"

	"github.com/netbirdio/netbird/management/server/permissions"

	"github.com/netbirdio/netbird/management/server/http/handlers/proxy"

	"github.com/netbirdio/netbird/management/server/auth"
	"github.com/netbirdio/netbird/management/server/geolocation"
	nbgroups "github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/http/handlers/accounts"
	"github.com/netbirdio/netbird/management/server/http/handlers/dns"
	"github.com/netbirdio/netbird/management/server/http/handlers/events"
	"github.com/netbirdio/netbird/management/server/http/handlers/groups"
	"github.com/netbirdio/netbird/management/server/http/handlers/idp"
	"github.com/netbirdio/netbird/management/server/http/handlers/instance"
	"github.com/netbirdio/netbird/management/server/http/handlers/networks"
	"github.com/netbirdio/netbird/management/server/http/handlers/peers"
	"github.com/netbirdio/netbird/management/server/http/handlers/policies"
	"github.com/netbirdio/netbird/management/server/http/handlers/routes"
	"github.com/netbirdio/netbird/management/server/http/handlers/setup_keys"
	"github.com/netbirdio/netbird/management/server/http/handlers/users"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
	nbinstance "github.com/netbirdio/netbird/management/server/instance"
	nbnetworks "github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

// NewAPIHandler creates the Management service HTTP API handler registering all the available endpoints.
func NewAPIHandler(ctx context.Context, router *mux.Router, accountManager account.Manager, networksManager nbnetworks.Manager, resourceManager resources.Manager, routerManager routers.Manager, groupsManager nbgroups.Manager, LocationManager geolocation.Geolocation, authManager auth.Manager, appMetrics telemetry.AppMetrics, permissionsManager permissions.Manager, settingsManager settings.Manager, zManager zones.Manager, rManager records.Manager, networkMapController network_map.Controller, idpManager idpmanager.Manager, serviceManager service.Manager, reverseProxyDomainManager *manager.Manager, reverseProxyAccessLogsManager accesslogs.Manager, proxyGRPCServer *nbgrpc.ProxyServiceServer, trustedHTTPProxies []netip.Prefix, corsAllowedOrigins []string, rateLimiter *middleware.APIRateLimiter, isValidChildAccount middleware.IsValidChildAccountFunc, agentNetworkManager agentnetwork.Manager) (http.Handler, error) {

	// Register bypass paths for unauthenticated endpoints
	if err := bypass.AddBypassPath("/api/instance"); err != nil {
		return nil, fmt.Errorf("failed to add bypass path: %w", err)
	}
	if err := bypass.AddBypassPath("/api/setup"); err != nil {
		return nil, fmt.Errorf("failed to add bypass path: %w", err)
	}
	// OAuth callback for proxy authentication
	if err := bypass.AddBypassPath(types.ProxyCallbackEndpointFull); err != nil {
		return nil, fmt.Errorf("failed to add bypass path: %w", err)
	}

	if rateLimiter == nil {
		log.Warn("NewAPIHandler: nil rate limiter, rate limiting disabled")
		rateLimiter = middleware.NewAPIRateLimiter(nil)
		rateLimiter.SetEnabled(false)
	}

	authMiddleware := middleware.NewAuthMiddleware(
		authManager,
		accountManager.GetAccountIDFromUserAuth,
		accountManager.SyncUserJWTGroups,
		accountManager.GetUserFromUserAuth,
		rateLimiter,
		appMetrics.GetMeter(),
		isValidChildAccount,
	)

	corsMiddleware := newCORSMiddleware(corsAllowedOrigins)

	metricsMiddleware := appMetrics.HTTPMiddleware()

	router.Use(metricsMiddleware.Handler, corsMiddleware.Handler, authMiddleware.Handler)

	instanceManager, err := nbinstance.NewManager(ctx, accountManager.GetStore(), idpManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance manager: %w", err)
	}

	accounts.AddEndpoints(accountManager, settingsManager, router)
	peers.AddEndpoints(accountManager, router, networkMapController, permissionsManager)
	users.AddEndpoints(accountManager, router)
	setup_keys.AddEndpoints(accountManager, router)
	policies.AddEndpoints(accountManager, LocationManager, router)
	policies.AddPostureCheckEndpoints(accountManager, LocationManager, router)
	policies.AddLocationsEndpoints(accountManager, LocationManager, permissionsManager, router)
	groups.AddEndpoints(accountManager, router)
	routes.AddEndpoints(accountManager, router)
	dns.AddEndpoints(accountManager, router)
	events.AddEndpoints(accountManager, router)
	networks.AddEndpoints(networksManager, resourceManager, routerManager, groupsManager, accountManager, router)
	zonesManager.RegisterEndpoints(router, zManager)
	recordsManager.RegisterEndpoints(router, rManager)
	idp.AddEndpoints(accountManager, router)
	if agentNetworkManager != nil {
		agentnetworkhandlers.RegisterEndpoints(agentNetworkManager, router)
	}
	instance.AddEndpoints(instanceManager, accountManager, router)
	instance.AddVersionEndpoint(instanceManager, router)
	if serviceManager != nil && reverseProxyDomainManager != nil {
		reverseproxymanager.RegisterEndpoints(serviceManager, *reverseProxyDomainManager, reverseProxyAccessLogsManager, permissionsManager, router)
	}

	proxytoken.RegisterEndpoints(accountManager.GetStore(), permissionsManager, router)

	// Register OAuth callback handler for proxy authentication
	if proxyGRPCServer != nil {
		oauthHandler := proxy.NewAuthCallbackHandler(proxyGRPCServer, trustedHTTPProxies)
		oauthHandler.RegisterEndpoints(router)
	}

	return router, nil
}

// newCORSMiddleware limits cross-origin API access to explicitly configured
// origins. Same-origin requests require no CORS response headers and continue
// to work when the allow-list is empty.
func newCORSMiddleware(allowedOrigins []string) *cors.Cors {
	allowedOriginSet := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowedOriginSet[origin] = struct{}{}
	}

	return cors.New(cors.Options{
		// rs/cors treats an empty AllowedOrigins slice as "*". Use its callback
		// instead so an omitted setting denies every cross-origin request.
		// Matching exact origin strings also keeps this setting an allow-list:
		// wildcards, including "*", are never implicitly accepted.
		AllowOriginFunc: func(origin string) bool {
			_, ok := allowedOriginSet[origin]
			return ok
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodHead,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
		},
		AllowedHeaders: []string{
			"Authorization",
			"Content-Type",
		},
	})
}
