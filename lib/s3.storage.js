class S3Storage {

	constructor(s3, bucket) {
		this.s3 = s3;
		this.bucket = bucket;
	}

	/**
	 *
	 * @param prefix
	 * @param cb function (error, data)
	 */
	listObjects(prefix, cb) {
		this.s3.listObjects({
			Bucket: this.bucket,
			Prefix: prefix
		}, cb);
	}

	upload(key, body, cb) {
		this.s3.upload({
			Bucket: this.bucket,
			Key: key,
			Body: body
		}, cb);
	}

	getObject(key, range, cb) {
		this.s3.getObject({
			Bucket: this.bucket,
			Key: key,
			Range: range
		}, cb);
	}

	deleteObject(key, cb) {
		this.s3.deleteObject({
			Bucket: this.bucket,
			Key: key
		}, cb);
	}

	deleteObjects(keys, cb) {
		this.s3.deleteObjects({
			Bucket: this.bucket,
			Delete: {
				Objects: keys
			}
		}, cb);
	}

	putObject(key, body, cb) {
		this.s3.putObject({
			Bucket: this.bucket,
			Key: key,
			Body: body
		}, cb);
	}

	copyObject(key, copySource, cb) {
		this.s3.copyObject({
			Bucket: this.bucket,
			Key: key,
			CopySource: copySource
		}, cb);
	}

}

module.exports = S3Storage;
