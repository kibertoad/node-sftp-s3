class S3Storage {

	constructor(s3) {
		this.s3 = s3;
	}

	/**
	 *
	 * @param prefix
	 * @param cb function (error, data)
	 */
	listObjects(prefix, cb) {
		this.s3.listObjects({
			Prefix: prefix
		}, cb);
	}

	upload(key, body, cb) {
		this.s3.upload({
			Key: key,
			Body: body
		}, cb);
	}

	getObject(key, range, cb) {
		this.s3.getObject({
			Key: key,
			Range: range
		}, cb);
	}

	deleteObject(key, cb) {
		this.s3.deleteObject({
			Key: key
		}, cb);
	}

	deleteObjects(keys, cb) {
		this.s3.deleteObjects({
			Delete: {
				Objects: keys
			}
		}, cb);
	}

	putObject(key, body, cb) {
		this.s3.putObject({
			Key: key,
			Body: body
		}, cb);
	}

	copyObject(key, copySource, cb) {
		this.s3.copyObject({
			Key: key,
			CopySource: copySource
		}, cb);
	}

}

module.exports = S3Storage;
