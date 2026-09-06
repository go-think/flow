package flow

// Option defines a functional configuration option for the router.
type Option func(*router)

// WithSignatureKey sets the secret HMAC key for signed URLs.
func WithSignatureKey(key string) Option {
	return func(r *router) {
		r.signatureKey = key
	}
}

// WithParameterResolver configures a custom parameter resolver for route handler invocation.
func WithParameterResolver(resolver ParameterResolver) Option {
	return func(r *router) {
		r.parameterResolver = resolver
	}
}
