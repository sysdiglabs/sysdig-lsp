use tower_lsp::{Client, lsp_types::MessageType};
use tracing::{Level, Subscriber};
use tracing_subscriber::Layer;

pub struct LSPLogger {
    client: Client,
}

impl LSPLogger {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

impl<S> Layer<S> for LSPLogger
where
    S: Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = *event.metadata().level();
        let message_type = match level {
            Level::ERROR => MessageType::ERROR,
            Level::WARN => MessageType::WARNING,
            Level::INFO => MessageType::INFO,
            Level::DEBUG => MessageType::LOG,
            Level::TRACE => return,
        };

        let mut visitor = StringVisitor::default();
        event.record(&mut visitor);
        let message = visitor.message;

        let join_handle = tokio::spawn({
            let client = self.client.clone();
            async move {
                client.log_message(message_type, message).await;
            }
        });

        std::mem::drop(join_handle); // no need to handle it
    }
}

#[derive(Default)]
struct StringVisitor {
    message: String,
}

impl tracing::field::Visit for StringVisitor {
    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if !self.message.is_empty() {
            self.message.push(' ');
        }
        self.message.push_str(&format!("{value:?}"));
    }
}
