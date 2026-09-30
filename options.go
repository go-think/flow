package flow

// SetSignatureKey sets the secret HMAC key for signed URLs
// .
func (r *router) SetSignatureKey(key string) {
	r.signatureKey = key
}

// SetParameterResolver sets the dependency resolver used to inject handler
// parameters by type.
func (r *router) SetParameterResolver(resolver ParameterResolver) {
	r.parameterResolver = resolver
}
