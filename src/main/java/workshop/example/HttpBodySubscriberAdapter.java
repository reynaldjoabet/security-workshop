package example.datastream;

import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.Flow;

final class HttpBodySubscriberAdapter<I> implements Flow.Subscriber<ByteBuffer> {

	private final HttpResponse.BodySubscriber<I> upstream;

	HttpBodySubscriberAdapter(HttpResponse.BodySubscriber<I> upstream) {
		this.upstream = upstream;
	}

	@Override
	public void onComplete() {
		upstream.onComplete();
	}

	@Override
	public void onError(Throwable throwable) {
		upstream.onError(throwable);
	}

	@Override
	public void onNext(ByteBuffer item) {
		upstream.onNext(List.of(item));
	}

	@Override
	public void onSubscribe(Flow.Subscription subscription) {
		upstream.onSubscribe(subscription);
	}
}