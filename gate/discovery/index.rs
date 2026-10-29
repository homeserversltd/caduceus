use serde_json::Value;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteStep {
    pub rust: Option<String>,
    pub snake: Option<String>,
    pub stage_id: Option<String>,
    pub arguments: Option<Value>,
    pub required: bool,
    pub depends_on: Vec<String>,
    pub deadline_seconds: Option<u64>,
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
        let stage_id = object.get("stage_id").and_then(Value::as_str).map(ToOwned::to_owned);
        let arguments = object.get("arguments").filter(|value| value.is_object()).cloned();
        let required = object.get("required").and_then(Value::as_bool).unwrap_or(true);
        let depends_on = object.get("depends_on").and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).map(ToOwned::to_owned).collect())
            .unwrap_or_default();
        let deadline_seconds = object.get("deadline_seconds").and_then(Value::as_u64);
        Ok(Self { rust, snake, stage_id, arguments, required, depends_on, deadline_seconds })
    }
}
pub fn walk_compiled_route_set(route_set: &[Value]) -> Result<Vec<RouteStep>, String> {
    route_set.iter().map(RouteStep::from_value).collect()
}
