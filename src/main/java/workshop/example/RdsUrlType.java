package workshop.example;

public enum RdsUrlType {
	IP_ADDRESS(false, false, false), RDS_WRITER_CLUSTER(true, true, true), RDS_READER_CLUSTER(true, true, true),
	RDS_CUSTOM_CLUSTER(true, true, true), RDS_PROXY(true, false, true), RDS_PROXY_ENDPOINT(true, false, true),
	RDS_INSTANCE(true, false, true), RDS_AURORA_LIMITLESS_DB_SHARD_GROUP(true, false, true),
	RDS_GLOBAL_WRITER_CLUSTER(true, true, false), OTHER(false, false, false);

	private final boolean isRds;
	private final boolean isRdsCluster;
	private final boolean hasRegion;

	RdsUrlType(final boolean isRds, final boolean isRdsCluster, final boolean hasRegion) {
		this.isRds = isRds;
		this.isRdsCluster = isRdsCluster;
		this.hasRegion = hasRegion;
	}

	public boolean isRds() {
		return this.isRds;
	}

	public boolean isRdsCluster() {
		return this.isRdsCluster;
	}

	public boolean hasRegion() {
		return hasRegion;
	}
}