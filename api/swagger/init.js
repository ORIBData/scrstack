window.addEventListener('load', function () {
  SwaggerUIBundle({
    url: '/scrs/v1/docs/openapi.yaml',
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis]
  });
});
