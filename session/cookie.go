package session

type SessionRequest interface {
	Cookie(key string, value ...string) (string, error)
}

type SessionResponse interface {
	Cookie(name interface{}, params ...interface{}) error
}

type CookieHandler struct {
	request  SessionRequest
	response SessionResponse
}

func NewCookieHandler() *CookieHandler {
	return &CookieHandler{}
}

func (c *CookieHandler) SetRequest(req SessionRequest) {
	c.request = req
}

func (c *CookieHandler) SetResponse(res SessionResponse) {
	c.response = res
}

func (c *CookieHandler) Read(id string) string {
	if c.request == nil {
		return ""
	}
	value, _ := c.request.Cookie(id)
	return value
}

func (c *CookieHandler) Write(id string, data string) {
	if c.response == nil {
		return
	}
	_ = c.response.Cookie(id, data)
}
