use serde_json::Value;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteStep {
    pub rust: Option<String>,
    pub snake: Option<String>,
}
impl RouteStep {
    pub fn from_value(value: &Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "gate-route-step-not-object".to_string())?;
        let rust = object
            .get("rust")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let snake = object
            .get("snake")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if rust.is_none() == snake.is_none() {
            return Err("gate-route-step-must-name-one-band".into());
        }
        Ok(Self { rust, snake })
    }
}
pub fn walk_compiled_route_set(route_set: &[Value]) -> Result<Vec<RouteStep>, String> {
    route_set.iter().map(RouteStep::from_value).collect()
}
