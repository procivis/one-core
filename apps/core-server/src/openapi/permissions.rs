use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use http_body_util::BodyExt;
use reqwest::Method;
use utoipa::Modify;
use utoipa::openapi::path::Operation;

const PERMISSIONS_PLUGIN_SCRIPT: &str = include_str!("permissions-plugin.js");

/// Injects the Swagger-UI permission plugin into the served HTML content
pub async fn adapted_swagger_index(
    request: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let is_swagger_index = request.method() == Method::GET
        && matches!(
            request.uri().path(),
            "/swagger-ui/" | "/swagger-ui/index.html"
        );

    let response = next.run(request).await;

    if is_swagger_index {
        let (parts, body) = response.into_parts();

        let bytes = body.collect().await.ok().unwrap_or_default().to_bytes();
        let body = if let Ok(mut content) = String::from_utf8(bytes.to_vec()) {
            // insert the plugin script at the end of HTML body
            if let Some(pos) = content.rfind("</body>") {
                content.insert_str(
                    pos,
                    &format!("<script>{PERMISSIONS_PLUGIN_SCRIPT}</script>"),
                );
            }

            Body::from(content)
        } else {
            Body::from(bytes)
        };

        return Ok(Response::from_parts(parts, body));
    }

    Ok(response)
}

/// Modifies description of endpoints, adding declared permissions
pub struct PermissionsModifier;

impl Modify for PermissionsModifier {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        for (_, item) in openapi.paths.paths.as_mut_slice() {
            for operation in [
                item.get.as_mut(),
                item.put.as_mut(),
                item.post.as_mut(),
                item.delete.as_mut(),
                item.patch.as_mut(),
            ]
            .into_iter()
            .flatten()
            {
                modify_operation(operation);
            }
        }
    }
}

fn modify_operation(operation: &mut Operation) {
    let Some(permissions) = operation
        .extensions
        .as_ref()
        .and_then(|e| e.get("x-permissions"))
        .and_then(|v| v.as_array())
        .map(|vals| {
            vals.iter()
                .filter_map(|v| v.as_str())
                .map(|v| format!("<code>{v}</code>"))
                .collect::<Vec<_>>()
        })
    else {
        return;
    };

    if permissions.is_empty() {
        return;
    }

    let declaration = format!("<strong>Permissions:</strong> {}", permissions.join(" "));

    match operation.description.as_mut() {
        Some(description) => {
            description.insert_str(0, &format!("{declaration}\n\n"));
        }
        None => {
            operation.description = Some(declaration);
        }
    };
}
