from typing import List, Union
from schemas.common_event import CommonEvent
from pipeline.normalization import Normalizer


class IngestionPipeline:
    """
    Event ingestion and preprocessing pipeline.

    Responsible for:
        - Accepting single or batched events
        - Normalizing raw event data
        - Queuing events for downstream processing (rule engine, ML, correlation)
    """

    def __init__(self):
        # In-memory queue for processed events
        self.queue: List[CommonEvent] = []

        # Persistent normalizer instance for consistent event formatting
        self.normalizer = Normalizer()

    def ingest(self, events: Union[CommonEvent, List[CommonEvent]]) -> None:
        """
        Ingest single or multiple events into the pipeline.

        Args:
            events: A single CommonEvent or a list of CommonEvent objects.
        """
        if isinstance(events, list):
            for event in events:
                self._normalize_and_push(event)
        else:
            self._normalize_and_push(events)

    def _normalize_and_push(self, event: CommonEvent) -> None:
        """
        Normalize and enqueue a single event.

        This step ensures all events follow a consistent schema before
        being processed by downstream security components.
        """
        try:
            clean_event = self.normalizer.normalize(event)
            self.queue.append(clean_event)

        except ValueError as e:
            # In production, invalid events would go to a dead-letter queue or log system
            print(f"Dropping event {event.event_id}: {e}")

    def fetch_batch(self, size: int) -> List[CommonEvent]:
        """
        Retrieve and remove a batch of events from the queue.

        Args:
            size: Maximum number of events to return.

        Returns:
            List of queued CommonEvent objects.
        """
        batch = self.queue[:size]
        self.queue = self.queue[size:]
        return batch

    def get_queue_size(self) -> int:
        """
        Get current number of events waiting in the pipeline.

        Returns:
            int: Queue size
        """
        return len(self.queue)