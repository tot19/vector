use vector_lib::{
    NamedInternalEvent, counter,
    internal_event::{CounterName, InternalEvent, error_stage, error_type},
};

#[derive(Debug, NamedInternalEvent)]
pub struct SnmpTrapParseError {
    pub error: String,
    pub error_code: &'static str,
}

impl InternalEvent for SnmpTrapParseError {
    fn emit(self) {
        error!(
            message = "Error parsing SNMP trap.",
            error = %self.error,
            error_code = self.error_code,
            error_type = error_type::PARSER_FAILED,
            stage = error_stage::PROCESSING,
            internal_log_rate_limit = true,
        );
        counter!(
            CounterName::ComponentErrorsTotal,
            "error_code" => self.error_code,
            "error_type" => error_type::PARSER_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
    }
}
