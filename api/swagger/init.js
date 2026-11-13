window.addEventListener('load', function () {
  SwaggerUIBundle({
    url: '/scrs/v1/docs/openapi.yaml',
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis],
    // Tags stay in contract order; operations start collapsed with a filter box.
    docExpansion: 'list',
    defaultModelsExpandDepth: 0,
    filter: true,
    displayOperationId: true,
    displayRequestDuration: true,
    // Keeps the bearer token across reloads in this browser only.
    persistAuthorization: true,
    tryItOutEnabled: false
  });
});
