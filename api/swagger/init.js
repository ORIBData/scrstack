window.addEventListener('load', function () {
  SwaggerUIBundle({
    url: '/scrs/v1/docs/openapi.yaml',
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis],
    // Tags stay in contract order and start collapsed so the page opens as a
    // short list of areas; the filter box finds an operation by name or path.
    // Schemas stay available at the bottom for people generating types.
    docExpansion: 'none',
    defaultModelsExpandDepth: 1,
    defaultModelExpandDepth: 2,
    filter: true,
    displayOperationId: true,
    displayRequestDuration: true,
    // Tokens are long-lived secrets: never keep them in browser storage.
    persistAuthorization: false,
    // Read-only on purpose: a token typed into a shared docs page is a secret in
    // a browser. Try calls from your own client or n8n.
    tryItOutEnabled: false
  });
});
