package templates

import "text/template"

var templates = map[string]string{"additional-properties.tmpl": `{{range .Types}}{{$addType := .Schema.AdditionalPropertiesType.TypeDecl}}

// Getter for additional properties for {{.TypeName}}. Returns the specified
// element and whether it was found
func (a {{.TypeName}}) Get(fieldName string) (value {{$addType}}, found bool) {
    if a.AdditionalProperties != nil {
        value, found = a.AdditionalProperties[fieldName]
    }
    return
}

// Setter for additional properties for {{.TypeName}}
func (a *{{.TypeName}}) Set(fieldName string, value {{$addType}}) {
    if a.AdditionalProperties == nil {
        a.AdditionalProperties = make(map[string]{{$addType}})
    }
    a.AdditionalProperties[fieldName] = value
}

// Override default JSON handling for {{.TypeName}} to handle AdditionalProperties
func (a *{{.TypeName}}) UnmarshalJSON(b []byte) error {
    object := make(map[string]json.RawMessage)
	err := json.Unmarshal(b, &object)
	if err != nil {
		return err
	}
{{range .Schema.Properties}}
    if raw, found := object["{{.JsonFieldName}}"]; found {
        err = json.Unmarshal(raw, &a.{{.GoFieldName}})
        if err != nil {
            return fmt.Errorf("error reading '{{.JsonFieldName}}': %w", err)
        }
        delete(object, "{{.JsonFieldName}}")
    }
{{end}}
    if len(object) != 0 {
        a.AdditionalProperties = make(map[string]{{$addType}})
        for fieldName, fieldBuf := range object {
            var fieldVal {{$addType}}
            err := json.Unmarshal(fieldBuf, &fieldVal)
            if err != nil {
                return fmt.Errorf("error unmarshaling field %s: %w", fieldName, err)
            }
            a.AdditionalProperties[fieldName] = fieldVal
        }
    }
	return nil
}

// Override default JSON handling for {{.TypeName}} to handle AdditionalProperties
func (a {{.TypeName}}) MarshalJSON() ([]byte, error) {
    var err error
    object := make(map[string]json.RawMessage)
{{range .Schema.Properties}}
{{if not .Required}}if a.{{.GoFieldName}} != nil { {{end}}
    object["{{.JsonFieldName}}"], err = json.Marshal(a.{{.GoFieldName}})
    if err != nil {
        return nil, fmt.Errorf("error marshaling '{{.JsonFieldName}}': %w", err)
    }
{{if not .Required}} }{{end}}
{{end}}
    for fieldName, field := range a.AdditionalProperties {
		object[fieldName], err = json.Marshal(field)
		if err != nil {
			return nil, fmt.Errorf("error marshaling '%s': %w", fieldName, err)
		}
	}
	return json.Marshal(object)
}
{{end}}
`,
	"chi-handler.tmpl": `// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
  return HandlerWithOptions(si, ChiServerOptions{})
}

type ChiServerOptions struct {
    BaseURL string
    BaseRouter chi.Router
    Middlewares []MiddlewareFunc
    ErrorHandlerFunc   func(w http.ResponseWriter, r *http.Request, err error)
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
    return HandlerWithOptions(si, ChiServerOptions {
        BaseRouter: r,
    })
}

func HandlerFromMuxWithBaseURL(si ServerInterface, r chi.Router, baseURL string) http.Handler {
    return HandlerWithOptions(si, ChiServerOptions {
        BaseURL: baseURL,
        BaseRouter: r,
    })
}

// HandlerWithOptions creates http.Handler with additional options
func HandlerWithOptions(si ServerInterface, options ChiServerOptions) http.Handler {
r := options.BaseRouter

if r == nil {
r = chi.NewRouter()
}
if options.ErrorHandlerFunc == nil {
    options.ErrorHandlerFunc = func(w http.ResponseWriter, r *http.Request, err error) {
        http.Error(w, err.Error(), http.StatusBadRequest)
    }
}
{{if .}}wrapper := ServerInterfaceWrapper{
Handler: si,
HandlerMiddlewares: options.Middlewares,
ErrorHandlerFunc: options.ErrorHandlerFunc,
}
{{end}}
{{range .}}r.Group(func(r chi.Router) {
r.{{.Method | lower | title }}(options.BaseURL+"{{.Path | swaggerUriToChiUri}}", wrapper.{{.OperationId}})
})
{{end}}
return r
}
`,
	"chi-interface.tmpl": `// ServerInterface represents all server handlers.
type ServerInterface interface {
{{range .}}{{.SummaryAsComment }}
// ({{.Method}} {{.Path}})
{{.OperationId}}(w http.ResponseWriter, r *http.Request{{genParamArgs .PathParams}}{{if .RequiresParamObject}}, params {{.OperationId}}Params{{end}})
{{end}}
}
`,
	"chi-middleware.tmpl": `// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
    Handler ServerInterface
    HandlerMiddlewares []MiddlewareFunc
    ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

type MiddlewareFunc func(http.HandlerFunc) http.HandlerFunc

{{range .}}{{$opid := .OperationId}}

// {{$opid}} operation middleware
func (siw *ServerInterfaceWrapper) {{$opid}}(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  {{if or .RequiresParamObject (gt (len .PathParams) 0) }}
  var err error
  {{end}}

  {{range .PathParams}}// ------------- Path parameter "{{.ParamName}}" -------------
  var {{$varName := .GoVariableName}}{{$varName}} {{.TypeDef}}

  {{if .IsPassThrough}}
  {{$varName}} = chi.URLParam(r, "{{.ParamName}}")
  {{end}}
  {{if .IsJson}}
  err = json.Unmarshal([]byte(chi.URLParam(r, "{{.ParamName}}")), &{{$varName}})
  if err != nil {
    siw.ErrorHandlerFunc(w, r, &UnmarshalingParamError{ParamName: "{{.ParamName}}", Err: err})
    return
  }
  {{end}}
  {{if .IsStyled}}
  err = runtime.BindStyledParameter("{{.Style}}",{{.Explode}}, "{{.ParamName}}", chi.URLParam(r, "{{.ParamName}}"), &{{$varName}})
  if err != nil {
    siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "{{.ParamName}}", Err: err})
    return
  }
  {{end}}

  {{end}}

{{range .SecurityDefinitions}}
  ctx = context.WithValue(ctx, {{.ProviderName | ucFirst}}Scopes, {{toStringArray .Scopes}})
{{end}}

  {{if .RequiresParamObject}}
    // Parameter object where we will unmarshal all parameters from the context
    var params {{.OperationId}}Params

    {{range $paramIdx, $param := .QueryParams}}// ------------- {{if .Required}}Required{{else}}Optional{{end}} query parameter "{{.ParamName}}" -------------
      if paramValue := r.URL.Query().Get("{{.ParamName}}"); paramValue != "" {

      {{if .IsPassThrough}}
        params.{{.GoName}} = {{if not .Required}}&{{end}}paramValue
      {{end}}

      {{if .IsJson}}
        var value {{.TypeDef}}
        err = json.Unmarshal([]byte(paramValue), &value)
        if err != nil {
          siw.ErrorHandlerFunc(w, r, &UnmarshalingParamError{ParamName: "{{.ParamName}}", Err: err})
          return
        }

        params.{{.GoName}} = {{if not .Required}}&{{end}}value
      {{end}}
      }{{if .Required}} else {
          siw.ErrorHandlerFunc(w, r, &RequiredParamError{ParamName: "{{.ParamName}}"})
          return
      }{{end}}
      {{if .IsStyled}}
      err = runtime.BindQueryParameter("{{.Style}}", {{.Explode}}, {{.Required}}, "{{.ParamName}}", r.URL.Query(), &params.{{.GoName}})
      if err != nil {
        siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "{{.ParamName}}", Err: err})
        return
      }
      {{end}}
  {{end}}

    {{if .HeaderParams}}
      headers := r.Header

      {{range .HeaderParams}}// ------------- {{if .Required}}Required{{else}}Optional{{end}} header parameter "{{.ParamName}}" -------------
        if valueList, found := headers[http.CanonicalHeaderKey("{{.ParamName}}")]; found {
          var {{.GoName}} {{.TypeDef}}
          n := len(valueList)
          if n != 1 {
            siw.ErrorHandlerFunc(w, r, &TooManyValuesForParamError{ParamName: "{{.ParamName}}", Count: n})
            return
          }

        {{if .IsPassThrough}}
          params.{{.GoName}} = {{if not .Required}}&{{end}}valueList[0]
        {{end}}

        {{if .IsJson}}
          err = json.Unmarshal([]byte(valueList[0]), &{{.GoName}})
          if err != nil {
            siw.ErrorHandlerFunc(w, r, &UnmarshalingParamError{ParamName: "{{.ParamName}}", Err: err})
            return
          }
        {{end}}

        {{if .IsStyled}}
          err = runtime.BindStyledParameterWithLocation("{{.Style}}",{{.Explode}}, "{{.ParamName}}", runtime.ParamLocationHeader, valueList[0], &{{.GoName}})
          if err != nil {
            siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "{{.ParamName}}", Err: err})
            return
          }
        {{end}}

          params.{{.GoName}} = {{if not .Required}}&{{end}}{{.GoName}}

        } {{if .Required}}else {
            err := fmt.Errorf("Header parameter {{.ParamName}} is required, but not found")
            siw.ErrorHandlerFunc(w, r, &RequiredHeaderError{ParamName: "{{.ParamName}}", Err: err})
            return
        }{{end}}

      {{end}}
    {{end}}

    {{range .CookieParams}}
      var cookie *http.Cookie

      if cookie, err = r.Cookie("{{.ParamName}}"); err == nil {

      {{- if .IsPassThrough}}
        params.{{.GoName}} = {{if not .Required}}&{{end}}cookie.Value
      {{end}}

      {{- if .IsJson}}
        var value {{.TypeDef}}
        var decoded string
        decoded, err := url.QueryUnescape(cookie.Value)
        if err != nil {
          err = fmt.Errorf("Error unescaping cookie parameter '{{.ParamName}}'")
          siw.ErrorHandlerFunc(w, r, &UnescapedCookieParamError{ParamName: "{{.ParamName}}", Err: err})
          return
        }

        err = json.Unmarshal([]byte(decoded), &value)
        if err != nil {
          siw.ErrorHandlerFunc(w, r, &UnmarshalingParamError{ParamName: "{{.ParamName}}", Err: err})
          return
        }

        params.{{.GoName}} = {{if not .Required}}&{{end}}value
      {{end}}

      {{- if .IsStyled}}
        var value {{.TypeDef}}
        err = runtime.BindStyledParameter("simple",{{.Explode}}, "{{.ParamName}}", cookie.Value, &value)
        if err != nil {
          siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "{{.ParamName}}", Err: err})
          return
        }
        params.{{.GoName}} = {{if not .Required}}&{{end}}value
      {{end}}

      }

      {{- if .Required}} else {
        siw.ErrorHandlerFunc(w, r, &RequiredParamError{ParamName: "{{.ParamName}}"})
        return
      }
      {{- end}}
    {{end}}
  {{end}}

  var handler = func(w http.ResponseWriter, r *http.Request) {
    siw.Handler.{{.OperationId}}(w, r{{genParamNames .PathParams}}{{if .RequiresParamObject}}, params{{end}})
}

  for _, middleware := range siw.HandlerMiddlewares {
    handler = middleware(handler)
  }

  handler(w, r.WithContext(ctx))
}
{{end}}

type UnescapedCookieParamError struct {
    ParamName string
  	Err error
}

func (e *UnescapedCookieParamError) Error() string {
    return fmt.Sprintf("error unescaping cookie parameter '%s'", e.ParamName)
}

func (e *UnescapedCookieParamError) Unwrap() error {
    return e.Err
}

type UnmarshalingParamError struct {
    ParamName string
    Err error
}

func (e *UnmarshalingParamError) Error() string {
    return fmt.Sprintf("Error unmarshaling parameter %s as JSON: %s", e.ParamName, e.Err.Error())
}

func (e *UnmarshalingParamError) Unwrap() error {
    return e.Err
}

type RequiredParamError struct {
    ParamName string
}

func (e *RequiredParamError) Error() string {
    return fmt.Sprintf("Query argument %s is required, but not found", e.ParamName)
}

type RequiredHeaderError struct {
    ParamName string
    Err error
}

func (e *RequiredHeaderError) Error() string {
    return fmt.Sprintf("Header parameter %s is required, but not found", e.ParamName)
}

func (e *RequiredHeaderError) Unwrap() error {
    return e.Err
}

type InvalidParamFormatError struct {
    ParamName string
	  Err error
}

func (e *InvalidParamFormatError) Error() string {
    return fmt.Sprintf("Invalid format for parameter %s: %s", e.ParamName, e.Err.Error())
}

func (e *InvalidParamFormatError) Unwrap() error {
    return e.Err
}

type TooManyValuesForParamError struct {
    ParamName string
    Count int
}

func (e *TooManyValuesForParamError) Error() string {
    return fmt.Sprintf("Expected one value for %s, got %d", e.ParamName, e.Count)
}
`,
	"client-with-responses.tmpl": `// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
    ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
    client, err := NewClient(server, opts...)
    if err != nil {
        return nil, err
    }
    return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
{{range . -}}
{{$hasParams := .RequiresParamObject -}}
{{$pathParams := .PathParams -}}
{{$opid := .OperationId -}}
    // {{$opid}} request{{if .HasBody}} with any body{{end}}
    {{$opid}}{{if .HasBody}}WithBody{{end}}WithResponse(ctx context.Context{{genParamArgs .PathParams}}{{if .RequiresParamObject}}, params *{{$opid}}Params{{end}}{{if .HasBody}}, contentType string, body io.Reader{{end}}, reqEditors... RequestEditorFn) (*{{genResponseTypeName $opid}}, error)
{{range .Bodies}}
    {{$opid}}{{.Suffix}}WithResponse(ctx context.Context{{genParamArgs $pathParams}}{{if $hasParams}}, params *{{$opid}}Params{{end}}, body {{$opid}}{{.NameTag}}RequestBody, reqEditors... RequestEditorFn) (*{{genResponseTypeName $opid}}, error)
{{end}}{{/* range .Bodies */}}
{{end}}{{/* range . $opid := .OperationId */}}
}

{{range .}}{{$opid := .OperationId}}{{$op := .}}
type {{$opid | ucFirst}}Response struct {
    Body         []byte
	HTTPResponse *http.Response
    {{- range getResponseTypeDefinitions .}}
    {{.TypeName}} *{{.Schema.TypeDecl}}
    {{- end}}
}

// Status returns HTTPResponse.Status
func (r {{$opid | ucFirst}}Response) Status() string {
    if r.HTTPResponse != nil {
        return r.HTTPResponse.Status
    }
    return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r {{$opid | ucFirst}}Response) StatusCode() int {
    if r.HTTPResponse != nil {
        return r.HTTPResponse.StatusCode
    }
    return 0
}
{{end}}


{{range .}}
{{$opid := .OperationId -}}
{{/* Generate client methods (with responses)*/}}

// {{$opid}}{{if .HasBody}}WithBody{{end}}WithResponse request{{if .HasBody}} with arbitrary body{{end}} returning *{{$opid}}Response
func (c *ClientWithResponses) {{$opid}}{{if .HasBody}}WithBody{{end}}WithResponse(ctx context.Context{{genParamArgs .PathParams}}{{if .RequiresParamObject}}, params *{{$opid}}Params{{end}}{{if .HasBody}}, contentType string, body io.Reader{{end}}, reqEditors... RequestEditorFn) (*{{genResponseTypeName $opid}}, error){
    rsp, err := c.{{$opid}}{{if .HasBody}}WithBody{{end}}(ctx{{genParamNames .PathParams}}{{if .RequiresParamObject}}, params{{end}}{{if .HasBody}}, contentType, body{{end}}, reqEditors...)
    if err != nil {
        return nil, err
    }
    return Parse{{genResponseTypeName $opid | ucFirst}}(rsp)
}

{{$hasParams := .RequiresParamObject -}}
{{$pathParams := .PathParams -}}
{{$bodyRequired := .BodyRequired -}}
{{range .Bodies}}
func (c *ClientWithResponses) {{$opid}}{{.Suffix}}WithResponse(ctx context.Context{{genParamArgs $pathParams}}{{if $hasParams}}, params *{{$opid}}Params{{end}}, body {{$opid}}{{.NameTag}}RequestBody, reqEditors... RequestEditorFn) (*{{genResponseTypeName $opid}}, error) {
    rsp, err := c.{{$opid}}{{.Suffix}}(ctx{{genParamNames $pathParams}}{{if $hasParams}}, params{{end}}, body, reqEditors...)
    if err != nil {
        return nil, err
    }
    return Parse{{genResponseTypeName $opid | ucFirst}}(rsp)
}
{{end}}

{{end}}{{/* operations */}}

{{/* Generate parse functions for responses*/}}
{{range .}}{{$opid := .OperationId}}

// Parse{{genResponseTypeName $opid | ucFirst}} parses an HTTP response from a {{$opid}}WithResponse call
func Parse{{genResponseTypeName $opid | ucFirst}}(rsp *http.Response) (*{{genResponseTypeName $opid}}, error) {
    bodyBytes, err := ioutil.ReadAll(rsp.Body)
    defer func() { _ = rsp.Body.Close() }()
    if err != nil {
        return nil, err
    }

    response := {{genResponsePayload $opid}}

    {{genResponseUnmarshal .}}

    return response, nil
}
{{end}}{{/* range . $opid := .OperationId */}}

`,
	"client.tmpl": `// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
    // create a client with sane default values
    client := Client{
        Server: server,
    }
    // mutate client and add all optional params
    for _, o := range opts {
        if err := o(&client); err != nil {
            return nil, err
        }
    }
    // ensure the server URL always has a trailing slash
    if !strings.HasSuffix(client.Server, "/") {
        client.Server += "/"
    }
    // create httpClient, if not already present
    if client.Client == nil {
        client.Client = &http.Client{}
    }
    return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
{{range . -}}
{{$hasParams := .RequiresParamObject -}}
{{$pathParams := .PathParams -}}
{{$opid := .OperationId -}}
    // {{$opid}} request{{if .HasBody}} with any body{{end}}
    {{$opid}}{{if .HasBody}}WithBody{{end}}(ctx context.Context{{genParamArgs $pathParams}}{{if $hasParams}}, params *{{$opid}}Params{{end}}{{if .HasBody}}, contentType string, body io.Reader{{end}}, reqEditors... RequestEditorFn) (*http.Response, error)
{{range .Bodies}}
    {{$opid}}{{.Suffix}}(ctx context.Context{{genParamArgs $pathParams}}{{if $hasParams}}, params *{{$opid}}Params{{end}}, body {{$opid}}{{.NameTag}}RequestBody, reqEditors... RequestEditorFn) (*http.Response, error)
{{end}}{{/* range .Bodies */}}
{{end}}{{/* range . $opid := .OperationId */}}
}


{{/* Generate client methods */}}
{{range . -}}
{{$hasParams := .RequiresParamObject -}}
{{$pathParams := .PathParams -}}
{{$opid := .OperationId -}}

func (c *Client) {{$opid}}{{if .HasBody}}WithBody{{end}}(ctx context.Context{{genParamArgs $pathParams}}{{if $hasParams}}, params *{{$opid}}Params{{end}}{{if .HasBody}}, contentType string, body io.Reader{{end}}, reqEditors... RequestEditorFn) (*http.Response, error) {
    req, err := New{{$opid}}Request{{if .HasBody}}WithBody{{end}}(c.Server{{genParamNames .PathParams}}{{if $hasParams}}, params{{end}}{{if .HasBody}}, contentType, body{{end}})
    if err != nil {
        return nil, err
    }
    req = req.WithContext(ctx)
    if err := c.applyEditors(ctx, req, reqEditors); err != nil {
        return nil, err
    }
    return c.Client.Do(req)
}

{{range .Bodies}}
func (c *Client) {{$opid}}{{.Suffix}}(ctx context.Context{{genParamArgs $pathParams}}{{if $hasParams}}, params *{{$opid}}Params{{end}}, body {{$opid}}{{.NameTag}}RequestBody, reqEditors... RequestEditorFn) (*http.Response, error) {
    req, err := New{{$opid}}{{.Suffix}}Request(c.Server{{genParamNames $pathParams}}{{if $hasParams}}, params{{end}}, body)
    if err != nil {
        return nil, err
    }
    req = req.WithContext(ctx)
    if err := c.applyEditors(ctx, req, reqEditors); err != nil {
        return nil, err
    }
    return c.Client.Do(req)
}
{{end}}{{/* range .Bodies */}}
{{end}}

{{/* Generate request builders */}}
{{range .}}
{{$hasParams := .RequiresParamObject -}}
{{$pathParams := .PathParams -}}
{{$bodyRequired := .BodyRequired -}}
{{$opid := .OperationId -}}

{{range .Bodies}}
// New{{$opid}}Request{{.Suffix}} calls the generic {{$opid}} builder with {{.ContentType}} body
func New{{$opid}}Request{{.Suffix}}(server string{{genParamArgs $pathParams}}{{if $hasParams}}, params *{{$opid}}Params{{end}}, body {{$opid}}{{.NameTag}}RequestBody) (*http.Request, error) {
    var bodyReader io.Reader
    buf, err := json.Marshal(body)
    if err != nil {
        return nil, err
    }
    bodyReader = bytes.NewReader(buf)
    return New{{$opid}}RequestWithBody(server{{genParamNames $pathParams}}{{if $hasParams}}, params{{end}}, "{{.ContentType}}", bodyReader)
}
{{end}}

// New{{$opid}}Request{{if .HasBody}}WithBody{{end}} generates requests for {{$opid}}{{if .HasBody}} with any type of body{{end}}
func New{{$opid}}Request{{if .HasBody}}WithBody{{end}}(server string{{genParamArgs $pathParams}}{{if $hasParams}}, params *{{$opid}}Params{{end}}{{if .HasBody}}, contentType string, body io.Reader{{end}}) (*http.Request, error) {
    var err error
{{range $paramIdx, $param := .PathParams}}
    var pathParam{{$paramIdx}} string
    {{if .IsPassThrough}}
    pathParam{{$paramIdx}} = {{.GoVariableName}}
    {{end}}
    {{if .IsJson}}
    var pathParamBuf{{$paramIdx}} []byte
    pathParamBuf{{$paramIdx}}, err = json.Marshal({{.GoVariableName}})
    if err != nil {
        return nil, err
    }
    pathParam{{$paramIdx}} = string(pathParamBuf{{$paramIdx}})
    {{end}}
    {{if .IsStyled}}
    pathParam{{$paramIdx}}, err = runtime.StyleParamWithLocation("{{.Style}}", {{.Explode}}, "{{.ParamName}}", runtime.ParamLocationPath, {{.GoVariableName}})
    if err != nil {
        return nil, err
    }
    {{end}}
{{end}}
    serverURL, err := url.Parse(server)
    if err != nil {
        return nil, err
    }

    operationPath := fmt.Sprintf("{{genParamFmtString .Path}}"{{range $paramIdx, $param := .PathParams}}, pathParam{{$paramIdx}}{{end}})
    if operationPath[0] == '/' {
        operationPath = "." + operationPath
    }

    queryURL, err := serverURL.Parse(operationPath)
    if err != nil {
        return nil, err
    }

{{if .QueryParams}}
    queryValues := queryURL.Query()
{{range $paramIdx, $param := .QueryParams}}
    {{if not .Required}} if params.{{.GoName}} != nil { {{end}}
    {{if .IsPassThrough}}
    queryValues.Add("{{.ParamName}}", {{if not .Required}}*{{end}}params.{{.GoName}})
    {{end}}
    {{if .IsJson}}
    if queryParamBuf, err := json.Marshal({{if not .Required}}*{{end}}params.{{.GoName}}); err != nil {
        return nil, err
    } else {
        queryValues.Add("{{.ParamName}}", string(queryParamBuf))
    }

    {{end}}
    {{if .IsStyled}}
    if queryFrag, err := runtime.StyleParamWithLocation("{{.Style}}", {{.Explode}}, "{{.ParamName}}", runtime.ParamLocationQuery, {{if not .Required}}*{{end}}params.{{.GoName}}); err != nil {
        return nil, err
    } else if parsed, err := url.ParseQuery(queryFrag); err != nil {
       return nil, err
    } else {
       for k, v := range parsed {
           for _, v2 := range v {
               queryValues.Add(k, v2)
           }
       }
    }
    {{end}}
    {{if not .Required}}}{{end}}
{{end}}
    queryURL.RawQuery = queryValues.Encode()
{{end}}{{/* if .QueryParams */}}
    req, err := http.NewRequest("{{.Method}}", queryURL.String(), {{if .HasBody}}body{{else}}nil{{end}})
    if err != nil {
        return nil, err
    }

    {{if .HasBody}}req.Header.Add("Content-Type", contentType){{end}}
{{range $paramIdx, $param := .HeaderParams}}
    {{if not .Required}} if params.{{.GoName}} != nil { {{end}}
    var headerParam{{$paramIdx}} string
    {{if .IsPassThrough}}
    headerParam{{$paramIdx}} = {{if not .Required}}*{{end}}params.{{.GoName}}
    {{end}}
    {{if .IsJson}}
    var headerParamBuf{{$paramIdx}} []byte
    headerParamBuf{{$paramIdx}}, err = json.Marshal({{if not .Required}}*{{end}}params.{{.GoName}})
    if err != nil {
        return nil, err
    }
    headerParam{{$paramIdx}} = string(headerParamBuf{{$paramIdx}})
    {{end}}
    {{if .IsStyled}}
    headerParam{{$paramIdx}}, err = runtime.StyleParamWithLocation("{{.Style}}", {{.Explode}}, "{{.ParamName}}", runtime.ParamLocationHeader, {{if not .Required}}*{{end}}params.{{.GoName}})
    if err != nil {
        return nil, err
    }
    {{end}}
    req.Header.Set("{{.ParamName}}", headerParam{{$paramIdx}})
    {{if not .Required}}}{{end}}
{{end}}

{{range $paramIdx, $param := .CookieParams}}
    {{if not .Required}} if params.{{.GoName}} != nil { {{end}}
    var cookieParam{{$paramIdx}} string
    {{if .IsPassThrough}}
    cookieParam{{$paramIdx}} = {{if not .Required}}*{{end}}params.{{.GoName}}
    {{end}}
    {{if .IsJson}}
    var cookieParamBuf{{$paramIdx}} []byte
    cookieParamBuf{{$paramIdx}}, err = json.Marshal({{if not .Required}}*{{end}}params.{{.GoName}})
    if err != nil {
        return nil, err
    }
    cookieParam{{$paramIdx}} = url.QueryEscape(string(cookieParamBuf{{$paramIdx}}))
    {{end}}
    {{if .IsStyled}}
    cookieParam{{$paramIdx}}, err = runtime.StyleParamWithLocation("simple", {{.Explode}}, "{{.ParamName}}", runtime.ParamLocationCookie, {{if not .Required}}*{{end}}params.{{.GoName}})
    if err != nil {
        return nil, err
    }
    {{end}}
    cookie{{$paramIdx}} := &http.Cookie{
        Name:"{{.ParamName}}",
        Value:cookieParam{{$paramIdx}},
    }
    req.AddCookie(cookie{{$paramIdx}})
    {{if not .Required}}}{{end}}
{{end}}
    return req, nil
}

{{end}}{{/* Range */}}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
    for _, r := range c.RequestEditors {
        if err := r(ctx, req); err != nil {
            return err
        }
    }
    for _, r := range additionalEditors {
        if err := r(ctx, req); err != nil {
            return err
        }
    }
    return nil
}
`,
	"constants.tmpl": `{{- if gt (len .SecuritySchemeProviderNames) 0 }}
const (
{{range $ProviderName := .SecuritySchemeProviderNames}}
    {{- $ProviderName | ucFirst}}Scopes = "{{$ProviderName}}.Scopes"
{{end}}
)
{{end}}
{{if gt (len .EnumDefinitions) 0 }}
{{range $Enum := .EnumDefinitions}}
// Defines values for {{$Enum.TypeName}}.
const (
{{range $index, $value := $Enum.Schema.EnumValues}}
  {{$index}} {{$Enum.TypeName}} = {{$Enum.ValueWrapper}}{{$value}}{{$Enum.ValueWrapper}}
{{end}}
)
{{end}}
{{end}}
`,
	"echo-interface.tmpl": `// ServerInterface represents all server handlers.
type ServerInterface interface {
{{range .}}{{.SummaryAsComment }}
// ({{.Method}} {{.Path}})
{{.OperationId}}(ctx echo.Context{{genParamArgs .PathParams}}{{if .RequiresParamObject}}, params {{.OperationId}}Params{{end}}) error
{{end}}
}
`,
	"echo-register.tmpl": `

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router EchoRouter, si ServerInterface) {
    RegisterHandlersWithBaseURL(router, si, "")
}

// Registers handlers, and prepends BaseURL to the paths, so that the paths
// can be served under a prefix.
func RegisterHandlersWithBaseURL(router EchoRouter, si ServerInterface, baseURL string) {
{{if .}}
    wrapper := ServerInterfaceWrapper{
        Handler: si,
    }
{{end}}
{{range .}}router.{{.Method}}(baseURL + "{{.Path | swaggerUriToEchoUri}}", wrapper.{{.OperationId}})
{{end}}
}
`,
	"echo-wrappers.tmpl": `// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
    Handler ServerInterface
}

{{range .}}{{$opid := .OperationId}}// {{$opid}} converts echo context to params.
func (w *ServerInterfaceWrapper) {{.OperationId}} (ctx echo.Context) error {
    var err error
{{range .PathParams}}// ------------- Path parameter "{{.ParamName}}" -------------
    var {{$varName := .GoVariableName}}{{$varName}} {{.TypeDef}}
{{if .IsPassThrough}}
    {{$varName}} = ctx.Param("{{.ParamName}}")
{{end}}
{{if .IsJson}}
    err = json.Unmarshal([]byte(ctx.Param("{{.ParamName}}")), &{{$varName}})
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Error unmarshaling parameter '{{.ParamName}}' as JSON")
    }
{{end}}
{{if .IsStyled}}
    err = runtime.BindStyledParameterWithLocation("{{.Style}}",{{.Explode}}, "{{.ParamName}}", runtime.ParamLocationPath, ctx.Param("{{.ParamName}}"), &{{$varName}})
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter {{.ParamName}}: %s", err))
    }
{{end}}
{{end}}

{{range .SecurityDefinitions}}
    ctx.Set({{.ProviderName | sanitizeGoIdentity | ucFirst}}Scopes, {{toStringArray .Scopes}})
{{end}}

{{if .RequiresParamObject}}
    // Parameter object where we will unmarshal all parameters from the context
    var params {{.OperationId}}Params
{{range $paramIdx, $param := .QueryParams}}// ------------- {{if .Required}}Required{{else}}Optional{{end}} query parameter "{{.ParamName}}" -------------
    {{if .IsStyled}}
    err = runtime.BindQueryParameter("{{.Style}}", {{.Explode}}, {{.Required}}, "{{.ParamName}}", ctx.QueryParams(), &params.{{.GoName}})
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter {{.ParamName}}: %s", err))
    }
    {{else}}
    if paramValue := ctx.QueryParam("{{.ParamName}}"); paramValue != "" {
    {{if .IsPassThrough}}
    params.{{.GoName}} = {{if not .Required}}&{{end}}paramValue
    {{end}}
    {{if .IsJson}}
    var value {{.TypeDef}}
    err = json.Unmarshal([]byte(paramValue), &value)
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Error unmarshaling parameter '{{.ParamName}}' as JSON")
    }
    params.{{.GoName}} = {{if not .Required}}&{{end}}value
    {{end}}
    }{{if .Required}} else {
        return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Query argument {{.ParamName}} is required, but not found"))
    }{{end}}
    {{end}}
{{end}}

{{if .HeaderParams}}
    headers := ctx.Request().Header
{{range .HeaderParams}}// ------------- {{if .Required}}Required{{else}}Optional{{end}} header parameter "{{.ParamName}}" -------------
    if valueList, found := headers[http.CanonicalHeaderKey("{{.ParamName}}")]; found {
        var {{.GoName}} {{.TypeDef}}
        n := len(valueList)
        if n != 1 {
            return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Expected one value for {{.ParamName}}, got %d", n))
        }
{{if .IsPassThrough}}
        params.{{.GoName}} = {{if not .Required}}&{{end}}valueList[0]
{{end}}
{{if .IsJson}}
        err = json.Unmarshal([]byte(valueList[0]), &{{.GoName}})
        if err != nil {
            return echo.NewHTTPError(http.StatusBadRequest, "Error unmarshaling parameter '{{.ParamName}}' as JSON")
        }
{{end}}
{{if .IsStyled}}
        err = runtime.BindStyledParameterWithLocation("{{.Style}}",{{.Explode}}, "{{.ParamName}}", runtime.ParamLocationHeader, valueList[0], &{{.GoName}})
        if err != nil {
            return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter {{.ParamName}}: %s", err))
        }
{{end}}
        params.{{.GoName}} = {{if not .Required}}&{{end}}{{.GoName}}
        } {{if .Required}}else {
            return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Header parameter {{.ParamName}} is required, but not found"))
        }{{end}}
{{end}}
{{end}}

{{range .CookieParams}}
    if cookie, err := ctx.Cookie("{{.ParamName}}"); err == nil {
    {{if .IsPassThrough}}
    params.{{.GoName}} = {{if not .Required}}&{{end}}cookie.Value
    {{end}}
    {{if .IsJson}}
    var value {{.TypeDef}}
    var decoded string
    decoded, err := url.QueryUnescape(cookie.Value)
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Error unescaping cookie parameter '{{.ParamName}}'")
    }
    err = json.Unmarshal([]byte(decoded), &value)
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Error unmarshaling parameter '{{.ParamName}}' as JSON")
    }
    params.{{.GoName}} = {{if not .Required}}&{{end}}value
    {{end}}
    {{if .IsStyled}}
    var value {{.TypeDef}}
    err = runtime.BindStyledParameterWithLocation("simple",{{.Explode}}, "{{.ParamName}}", runtime.ParamLocationCookie, cookie.Value, &value)
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter {{.ParamName}}: %s", err))
    }
    params.{{.GoName}} = {{if not .Required}}&{{end}}value
    {{end}}
    }{{if .Required}} else {
        return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Query argument {{.ParamName}} is required, but not found"))
    }{{end}}

{{end}}{{/* .CookieParams */}}

{{end}}{{/* .RequiresParamObject */}}
    // Invoke the callback with all the unmarshalled arguments
    err = w.Handler.{{.OperationId}}(ctx{{genParamNames .PathParams}}{{if .RequiresParamObject}}, params{{end}})
    return err
}
{{end}}
`,
	"endpoint.tmpl": `type EndpointSet struct {
{{range .Ops}}
  {{.OperationId}}Endpoint    endpoint.Endpoint{{end}}
}

func NewEndpointSet(s Service, logger log.Factory, tracer opentracing.Tracer) EndpointSet { {{range .Ops}} 
  var {{lcFirst .OperationId}}Endpoint endpoint.Endpoint
	{
		{{lcFirst .OperationId}}Endpoint = make{{.OperationId}}Endpoint(s, logger)
		{{lcFirst .OperationId}}Endpoint = kittracing.TraceServer(tracer, "{{.OperationId}}")({{lcFirst .OperationId}}Endpoint)
	}{{end}}
	return EndpointSet{ {{range .Ops}}
		{{.OperationId}}Endpoint: {{lcFirst .OperationId}}Endpoint,{{end}}
	}
}

{{range .Ops}}
{{$opid := .OperationId -}}
{{$hasParams := .RequiresParamObject -}}
{{$pathParams := .PathParams -}}
{{$tag := .Tag -}}
// {{$opid}} 

type {{$opid}}Request struct {
  {{range .PathParams -}}
  {{camelCase .ParamName}} string
  {{end}}
  {{if .HasBody}}
  {{range .Bodies}}
  {{.Schema.RefType}} *{{.Schema.GoType}}
  {{end}}
  {{end}}
}

func make{{$opid}}Endpoint(s Service, logger log.Factory) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		logger.For(ctx).Info("{{$tag}}.{{$opid}}Endpoint received request")
		req := request.({{$opid}}Request)
		v, err := s.{{$opid}}(ctx{{range .PathParams -}}, req.{{camelCase .ParamName}}{{end}}{{range .Bodies}}, req.{{.Schema.GoType}}{{end}})
		if err != nil {
			return &v, err
		}
		return &v, nil
	}
}

{{end}}

`,
	"gin-interface.tmpl": `// ServerInterface represents all server handlers.
type ServerInterface interface {
{{range .}}{{.SummaryAsComment }}
// ({{.Method}} {{.Path}})
{{.OperationId}}(c *gin.Context{{genParamArgs .PathParams}}{{if .RequiresParamObject}}, params {{.OperationId}}Params{{end}})
{{end}}
}
`,
	"gin-register.tmpl": `// GinServerOptions provides options for the Gin server.
type GinServerOptions struct {
    BaseURL string
    Middlewares []MiddlewareFunc
}

// RegisterHandlers creates http.Handler with routing matching OpenAPI spec.
func RegisterHandlers(router *gin.Engine, si ServerInterface) *gin.Engine {
  return RegisterHandlersWithOptions(router, si, GinServerOptions{})
}

// RegisterHandlersWithOptions creates http.Handler with additional options
func RegisterHandlersWithOptions(router *gin.Engine, si ServerInterface, options GinServerOptions) *gin.Engine {
{{if .}}wrapper := ServerInterfaceWrapper{
Handler: si,
HandlerMiddlewares: options.Middlewares,
}
{{end}}
{{range .}}
router.{{.Method }}(options.BaseURL+"{{.Path | swaggerUriToGinUri }}", wrapper.{{.OperationId}})
{{end}}
return router
}
`,
	"gin-wrappers.tmpl": `// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
    Handler ServerInterface
    HandlerMiddlewares []MiddlewareFunc
}

type MiddlewareFunc func(c *gin.Context)

{{range .}}{{$opid := .OperationId}}

// {{$opid}} operation middleware
func (siw *ServerInterfaceWrapper) {{$opid}}(c *gin.Context) {

  {{if or .RequiresParamObject (gt (len .PathParams) 0) }}
  var err error
  {{end}}

  {{range .PathParams}}// ------------- Path parameter "{{.ParamName}}" -------------
  var {{$varName := .GoVariableName}}{{$varName}} {{.TypeDef}}

  {{if .IsPassThrough}}
  {{$varName}} = c.Query("{{.ParamName}}")
  {{end}}
  {{if .IsJson}}
  err = json.Unmarshal([]byte(c.Query("{{.ParamName}}")), &{{$varName}})
  if err != nil {
    c.JSON(http.StatusBadRequest, gin.H{"msg": "Error unmarshaling parameter '{{.ParamName}}' as JSON"})
    return
  }
  {{end}}
  {{if .IsStyled}}
  err = runtime.BindStyledParameter("{{.Style}}",{{.Explode}}, "{{.ParamName}}", c.Param("{{.ParamName}}"), &{{$varName}})
  if err != nil {
    c.JSON(http.StatusBadRequest, gin.H{"msg": fmt.Sprintf("Invalid format for parameter {{.ParamName}}: %s", err)})
    return
  }
  {{end}}

  {{end}}

{{range .SecurityDefinitions}}
  c.Set({{.ProviderName | ucFirst}}Scopes, {{toStringArray .Scopes}})
{{end}}

  {{if .RequiresParamObject}}
    // Parameter object where we will unmarshal all parameters from the context
    var params {{.OperationId}}Params

    {{range $paramIdx, $param := .QueryParams}}// ------------- {{if .Required}}Required{{else}}Optional{{end}} query parameter "{{.ParamName}}" -------------
      if paramValue := c.Query("{{.ParamName}}"); paramValue != "" {

      {{if .IsPassThrough}}
        params.{{.GoName}} = {{if not .Required}}&{{end}}paramValue
      {{end}}

      {{if .IsJson}}
        var value {{.TypeDef}}
        err = json.Unmarshal([]byte(paramValue), &value)
        if err != nil {
          c.JSON(http.StatusBadRequest, gin.H{"msg": "Error unmarshaling parameter '{{.ParamName}}' as JSON"})
          return
        }

        params.{{.GoName}} = {{if not .Required}}&{{end}}value
      {{end}}
      }{{if .Required}} else {
          c.JSON(http.StatusBadRequest, gin.H{"msg": "Query argument {{.ParamName}} is required, but not found"})
          return
      }{{end}}
      {{if .IsStyled}}
      err = runtime.BindQueryParameter("{{.Style}}", {{.Explode}}, {{.Required}}, "{{.ParamName}}", c.Request.URL.Query(), &params.{{.GoName}})
      if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"msg": fmt.Sprintf("Invalid format for parameter {{.ParamName}}: %s", err)})
        return
      }
      {{end}}
  {{end}}

    {{if .HeaderParams}}
      headers := r.Header

      {{range .HeaderParams}}// ------------- {{if .Required}}Required{{else}}Optional{{end}} header parameter "{{.ParamName}}" -------------
        if valueList, found := headers[http.CanonicalHeaderKey("{{.ParamName}}")]; found {
          var {{.GoName}} {{.TypeDef}}
          n := len(valueList)
          if n != 1 {
            c.JSON(http.StatusBadRequest, gin.H{"msg": fmt.Sprintf("Expected one value for {{.ParamName}}, got %d", n)})
            return
          }

        {{if .IsPassThrough}}
          params.{{.GoName}} = {{if not .Required}}&{{end}}valueList[0]
        {{end}}

        {{if .IsJson}}
          err = json.Unmarshal([]byte(valueList[0]), &{{.GoName}})
          if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"msg": "Error unmarshaling parameter '{{.ParamName}}' as JSON"})
            return
          }
        {{end}}

        {{if .IsStyled}}
          err = runtime.BindStyledParameterWithLocation("{{.Style}}",{{.Explode}}, "{{.ParamName}}", runtime.ParamLocationHeader, valueList[0], &{{.GoName}})
          if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"msg": fmt.Sprintf("Invalid format for parameter {{.ParamName}}: %s", err)})
            return
          }
        {{end}}

          params.{{.GoName}} = {{if not .Required}}&{{end}}{{.GoName}}

        } {{if .Required}}else {
            c.JSON(http.StatusBadRequest, gin.H{"msg": fmt.Sprintf("Header parameter {{.ParamName}} is required, but not found: %s", err)})
            return
        }{{end}}

      {{end}}
    {{end}}

    {{range .CookieParams}}
      var cookie *http.Cookie

      if cookie, err = c.Cookie("{{.ParamName}}"); err == nil {

      {{- if .IsPassThrough}}
        params.{{.GoName}} = {{if not .Required}}&{{end}}cookie.Value
      {{end}}

      {{- if .IsJson}}
        var value {{.TypeDef}}
        var decoded string
        decoded, err := url.QueryUnescape(cookie.Value)
        if err != nil {
          c.JSON(http.StatusBadRequest, gin.H{"msg": "Error unescaping cookie parameter '{{.ParamName}}'"})
          return
        }

        err = json.Unmarshal([]byte(decoded), &value)
        if err != nil {
          c.JSON(http.StatusBadRequest, gin.H{"msg": "Error unmarshaling parameter '{{.ParamName}}' as JSON"})
          return
        }

        params.{{.GoName}} = {{if not .Required}}&{{end}}value
      {{end}}

      {{- if .IsStyled}}
        var value {{.TypeDef}}
        err = runtime.BindStyledParameter("simple",{{.Explode}}, "{{.ParamName}}", cookie.Value, &value)
        if err != nil {
          c.JSON(http.StatusBadRequest, gin.H{"msg": "Invalid format for parameter {{.ParamName}}: %s"})
          return
        }
        params.{{.GoName}} = {{if not .Required}}&{{end}}value
      {{end}}

      }

      {{- if .Required}} else {
        c.JSON(http.StatusBadRequest, gin.H{"msg": "Query argument {{.ParamName}} is required, but not found"})
        return
      }
      {{- end}}
    {{end}}
  {{end}}

  for _, middleware := range siw.HandlerMiddlewares {
    middleware(c)
  }

  siw.Handler.{{.OperationId}}(c{{genParamNames .PathParams}}{{if .RequiresParamObject}}, params{{end}})
}
{{end}}
`,
	"go.mod.tmpl": `module github.com/12kmps/baas-{{.}}

go 1.17

require (
)

require (
)
`,
	"imports.tmpl": `{{if not .MutableFile}}
// DO NOT EDIT
// This file was code-generated by {{.ModuleName}} version {{.Version}} 
// It is expected that this file will be re-generated and overwitten to
// adapt to changes in the OpenAPI spec that was used to generate it
{{end}}
package {{.PackageName}}

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/12kmps/codegen-go/pkg/runtime"
	openapi_types "github.com/12kmps/codegen-go/pkg/types"

  "github.com/12kmps/baas/log"
	"github.com/12kmps/baas/tracing"
	"go.uber.org/zap"
	"github.com/go-kit/kit/endpoint"
	kittracing "github.com/go-kit/kit/tracing/opentracing"
	"github.com/opentracing/opentracing-go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormopentracing "gorm.io/plugin/opentracing"
 	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"


	{{- range .ExternalImports}}
	{{ . }}
	{{- end}}
)
`,
	"inline.tmpl": `// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{
{{range .SpecParts}}
    "{{.}}",{{end}}
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
    zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
    if err != nil {
        return nil, fmt.Errorf("error base64 decoding spec: %s", err)
    }
    zr, err := gzip.NewReader(bytes.NewReader(zipped))
    if err != nil {
        return nil, fmt.Errorf("error decompressing spec: %s", err)
    }
    var buf bytes.Buffer
    _, err = buf.ReadFrom(zr)
    if err != nil {
        return nil, fmt.Errorf("error decompressing spec: %s", err)
    }

    return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
    var res = make(map[string]func() ([]byte, error))
    if len(pathToFile) > 0 {
        res[pathToFile] = rawSpec
    }
    {{ if .ImportMapping }}
    pathPrefix := path.Dir(pathToFile)
    {{ end }}
    {{ range $key, $value := .ImportMapping }}
    for rawPath, rawFunc := range {{ $value.Name }}.PathToRawSpec(path.Join(pathPrefix, "{{ $key }}")) {
        if _, ok := res[rawPath]; ok {
            // it is not possible to compare functions in golang, so always overwrite the old value
        }
        res[rawPath] = rawFunc
    }
    {{- end }}
    return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
    var resolvePath = PathToRawSpec("")

    loader := openapi3.NewLoader()
    loader.IsExternalRefsAllowed = true
    loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
        var pathToFile = url.String()
        pathToFile = path.Clean(pathToFile)
        getSpec, ok := resolvePath[pathToFile]
        if !ok {
            err1 := fmt.Errorf("path not found: %s", pathToFile)
            return nil, err1
        }
        return getSpec()
    }
    var specData []byte
    specData, err = rawSpec()
    if err != nil {
        return
    }
    swagger, err = loader.LoadFromData(specData)
    if err != nil {
        return
    }
    return
}
`,
	"main.tmpl": `func main() {
	serviceName := "direct-debit"

	// Logging and Tracing
	logger, metricsFactory := log.Init(serviceName)
	tracer := tracing.Init(serviceName, metricsFactory, logger)

{{range . -}}
{{$tag := .Tag}}
{{$tagVar := .TagCamel}}
{{$tagPkg := .Package}}
  // {{$tag}} Service
  var {{$tagVar}}Router *mux.Router
  {
		repo, err := {{$tagPkg}}.NewGormRepository(context.Background(), os.Getenv("POSTGRES_DSN"), tracer, logger)
		if err != nil {
			logger.Bg().Fatal("Failed to create {{$tagPkg}} repository", zap.Error(err))
		}
		service := {{$tagPkg}}.NewService(repo, logger)
		endPoints := {{$tagPkg}}.NewEndpointSet(service, logger, tracer)
		{{$tagVar}}Router = {{$tagPkg}}.NewHTTPRouter(endPoints, logger, tracer)
  } 
{{end}}{{/* range . */}}

  m := tracing.NewServeMux(tracer)
	m.Handle("/metrics", promhttp.Handler()) // Prometheus
{{range . -}}
{{$tag := .Tag}}
{{$tagVar := .TagCamel}}
{{$tagPkg := .Package}}
	m.Handle("/{{kebabCase $tag}}/", {{$tagVar}}Router)
{{end}}{{/* range . */}}

	// Start Transports
	go func() error {
		// HTTP
		httpHost := ""
		httpPort := 8080
		httpAddr := httpHost + ":" + strconv.Itoa(httpPort)
		logger.Bg().Info("Listening", zap.String("transport", "http"), zap.String("host", httpHost), zap.Int("port", httpPort), zap.String("addr", httpAddr))
		err := http.ListenAndServe(httpAddr, m)
		logger.Bg().Fatal("Exit", zap.Error(err))
		return err
	}()

	// Select Loop
	select {}
}
`,
	"param-types.tmpl": `{{range .}}{{$opid := .OperationId}}
{{range .TypeDefinitions}}
// {{.TypeName}} defines parameters for {{$opid}}.
type {{.TypeName}} {{if and (opts.AliasTypes) (.CanAlias)}}={{end}} {{.Schema.TypeDecl}}
{{end}}
{{end}}
`,
	"repository-gorm.tmpl": `type repository struct {
	ctx context.Context
	db  *gorm.DB
}

func NewGormRepository(ctx context.Context, connString string, tracer opentracing.Tracer, logger log.Factory) (Repository, error) {
	var r Repository
	{
		db, err := gorm.Open(postgres.Open(connString), &gorm.Config{})
		if err != nil {
			logger.For(ctx).Fatal("Failed to open db", zap.Error(err))
		}

		db.Use(gormopentracing.New(gormopentracing.WithTracer(tracer)))

    {{range uniqueBodyTypes .Ops}}
		err = db.AutoMigrate(&{{.}}{})
		if err != nil {
			logger.For(ctx).Fatal("Failed to migrate db for type {{.}}", zap.Error(err))
		}
    {{end}}

		r = &repository{ctx: ctx, db: db}
	}

	return r, nil
}


{{range .Ops}}
{{$hasParams := .RequiresParamObject -}}
{{$pathParams := .PathParams -}}
{{$opid := .OperationId -}}
{{$tag := .Tag -}}
{{$successResponse := getSuccessResponseTypeDefinition .}}
  func (p *repository) {{$opid}}(ctx context.Context{{range .PathParams -}}, {{.ParamName}} string{{end}}{{range .Bodies}}, {{lcFirst .Schema.GoType}} *{{.Schema.GoType}}{{end}}) (*{{$successResponse.Schema.GoType}}, error) {
    {{if isCreate .}}
    var tx *gorm.DB
	  var v {{$successResponse.Schema.GoType}}
    {{$opBodies := .Bodies}}
    {{range $opBodies}}
    tx = p.db.WithContext(ctx).Create(&{{lcFirst .Schema.GoType}})
    if (tx.Error != nil) {
      return nil, tx.Error
    }
    {{end}}
    {{if isBoolResponseType $successResponse}}
    v = true
    {{end}}
    return &v, nil
    {{end}}
    {{if isGet .}}
	  var v {{$successResponse.Schema.GoType}}
	  tx := p.db.WithContext(ctx).First(&v, "id = ?", id)
	  if tx.Error == gorm.ErrRecordNotFound {
		  return nil, recorderrors.ErrNotFound
  	}
  	return &v, tx.Error
    {{end}}
    {{if isUpdate .}}
	  var v {{$successResponse.Schema.GoType}}
  	tx := p.db.WithContext(ctx).Model(&{{$tag}}{}).Where("id = ?", id).UpdateColumns(v)
	  if tx.RowsAffected == 0 {
		  return nil, recorderrors.ErrNotFound
	  }
	  v.ID = &id
  	return &v, tx.Error
    {{end}}
    {{if isOther .}}
    // TODO: Unable to generate code for this Operation
    return nil, errors.New("Not Implemented")
    {{end}}
  }
{{end}}

`,
	"repository.tmpl": `
{{$tag := .Tag}}
type Repository interface {
{{range .Ops}}
{{$opid := .OperationId -}}
{{$successResponse := getSuccessResponseTypeDefinition .}}
{{$tag := .Tag -}}{{$opid}}(ctx context.Context{{range .PathParams -}}, {{$paramName := .ParamName}}{{$paramName}} string{{end}}{{range .Bodies}}, {{lcFirst .Schema.GoType}} *{{.Schema.GoType}}{{end}}) (*{{$successResponse.Schema.GoType}}, error){{end}}
}
`,
	"request-bodies.tmpl": `{{range .}}{{$opid := .OperationId}}
{{range .Bodies}}
{{with .TypeDef $opid}}
// {{.TypeName}} defines body for {{$opid}} for application/json ContentType.
type {{.TypeName}} {{if and (opts.AliasTypes) (.CanAlias)}}={{end}} {{.Schema.TypeDecl}}
{{end}}
{{end}}
{{end}}
`,
	"service.tmpl": `{{$tag := .Tag}}
{{$tagVar := .TagCamel}}
{{$tagPkg := .Package}}
type Service interface {
{{range .Ops}}
{{$hasParams := .RequiresParamObject -}}
{{$pathParams := .PathParams -}}
{{$opid := .OperationId -}}
{{$successResponse := getSuccessResponseTypeDefinition .}}
{{$opid}}(ctx context.Context{{range .PathParams -}}, {{$paramName := .ParamName}}{{$paramName}} string{{end}}{{range .Bodies}}, {{lcFirst .Schema.GoType}} *{{.Schema.GoType}}{{end}}) (*{{$successResponse.Schema.GoType}}, error){{end}}
}

type service struct {
	repository Repository
}

func NewService(repository Repository, logger log.Factory) Service {
	var svc Service
	{
		svc = &service{
			repository: repository,
		}
	}
	return svc
}

{{range .Ops}}
{{$hasParams := .RequiresParamObject -}}
{{$pathParams := .PathParams -}}
{{$opid := .OperationId -}}
{{$successResponse := getSuccessResponseTypeDefinition .}}
{{$tag := .Tag -}}
  func (f *service) {{$opid}}(ctx context.Context{{range .PathParams -}}, {{.ParamName}} string{{end}}{{range .Bodies}}, {{lcFirst .Schema.GoType}} *{{.Schema.GoType}}{{end}}) (*{{$successResponse.Schema.GoType}}, error) {
    v, err := f.repository.{{$opid}}(ctx{{range .PathParams -}}, {{.ParamName}}{{end}}{{range .Bodies}}, {{lcFirst .Schema.GoType}}{{end}})
    return v, err
  }
{{end}}
`,
	"transport.tmpl": `{{$tag := .Tag}}

func NewHTTPRouter(endpoints EndpointSet, logger log.Factory, tracer opentracing.Tracer) *mux.Router {
	options := []httptransport.ServerOption{
		httptransport.ServerErrorEncoder(errorEncoder),
	}

  r := mux.NewRouter()

{{range .Ops}}
{{$hasParams := .RequiresParamObject -}}
{{$pathParams := .PathParams -}}
{{$opid := .OperationId -}}
	{{lcFirst .OperationId}}Handler := httptransport.NewServer(
		endpoints.{{$opid}}Endpoint,
		decode{{$opid}}Request,
		encodeResponse,
		options...,
	)
	r.Handle("{{.Path}}", {{lcFirst $opid}}Handler).Methods("{{.Method}}")
{{end}}

	return r
}

{{range .Ops}}
{{$pathParams := .PathParams -}}
{{$opid := .OperationId -}}

// {{$opid}}

func decode{{$opid}}Request(_ context.Context, r *http.Request) (interface{}, error) {
  {{range .Bodies}}var {{lcFirst .Schema.GoType}} {{.Schema.GoType}}{{end}}
  {{range .Bodies}}
	if err := json.NewDecoder(r.Body).Decode(&{{lcFirst .Schema.GoType}}); err != nil {
		return nil, err
	}{{end}}

  {{if hasEndpointRequestVars $pathParams}}
	vars := mux.Vars(r)
  {{end}}
	request := {{$opid}}Request{
    {{genEndpointRequestVars $pathParams}} {{range .Bodies}}{{.Schema.GoType}}: &{{lcFirst .Schema.GoType}},{{end}}
	}
	return request, nil
}
{{end}}

// Response Encoder (Generic)

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	return json.NewEncoder(w).Encode(response)
}

// Error Encoder

type errorResponse struct { 
  {{ genErrorStringVar }}
}

func errorEncoder(ctx context.Context, err error, w http.ResponseWriter) {
	if err == recorderrors.ErrNotFound {
		w.WriteHeader(http.StatusNotFound)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse{Error: err.Error()})
	}
}
`,
	"typedef.tmpl": `{{range .Types}}
{{ with .Schema.Description }}{{ . }}{{ else }}// {{.TypeName}} defines model for {{.JsonName}}.{{ end }}
type {{.TypeName}} {{if and (opts.AliasTypes) (.CanAlias)}}={{end}} {{.Schema.TypeDecl}}
{{end}}
`,
}

// Parse parses declared templates.
func Parse(t *template.Template) (*template.Template, error) {
	for name, s := range templates {
		var tmpl *template.Template
		if t == nil {
			t = template.New(name)
		}
		if name == t.Name() {
			tmpl = t
		} else {
			tmpl = t.New(name)
		}
		if _, err := tmpl.Parse(s); err != nil {
			return nil, err
		}
	}
	return t, nil
}

