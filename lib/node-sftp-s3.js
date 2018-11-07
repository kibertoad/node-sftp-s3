'use strict';

const crypto = require('crypto');
const _path = require('path');
const constants = require('constants');
const EventEmitter = require('events').EventEmitter;
const PassThrough = require('stream').PassThrough;

const moment = require('moment');
const _ = require('lodash');
const buffersEqual = require('buffer-equal-constant-time');
const ssh2 = require('ssh2');
const utils = ssh2.utils;
const OPEN_MODE = ssh2.SFTP_OPEN_MODE;
const STATUS_CODE = ssh2.SFTP_STATUS_CODE;

const util = require('util');

class SFTPServerStorage extends EventEmitter {

	/**
	 *
	 * @param storage - should implement: mkdir(name: string), save(name: string, content: readstream)
	 * @param {string} bucket
	 * @param authFn - function(ctx) - do ctx.resolve if successful, ctx.reject(Array<string> supportedAuthMethods) if
	 *     not
	 * @param postUploadCb function (storageId)
	 * @param {Object} defaultPubKey
	 * @param {Object} [logger]
	 */
	constructor(storage, bucket, authFn, postUploadCb, defaultPubKey, logger = console) {
    super();
    this.storage = storage;
    this.bucket = bucket;
    this.publicKeys = [];
    this.hostKeys = [];
    this.loggingEnabled = false;
    this.authFn = authFn;
    this.postUploadCb = postUploadCb;
    this.defaultPubKey = defaultPubKey;
    this.logger = logger;
  }

  /**
   * Enables logging to standard output
   */
  enableLogging() {
    this.loggingEnabled = true;
  }

  /**
   * Disables logging
   */
  disableLogging() {
    this.loggingEnabled = false;
  }

  /**
   * Adds a public key for authentication for a username
   *
   * @param {string} key
   * @param {string} username - username for specified key
   * @param {string} [ns] - Additional path prefix
   */
  addPublicKey(key, username, ns) {
	  const pubKey = utils.genPublicKey(utils.parseKey(key));
	  let path = _path.normalize(username);
	  if(ns) {
      path = _path.join(_path.normalize(ns), path);
    }

    while (path.indexOf('\\') >= 0)
      path = path.replace('\\', '/');

    this.publicKeys.push({ key: pubKey, username: username, path: path });
    this._log(util.format('Added public key for username %s, path %s', username, path));
  }

  /**
   * Remove the public key for a username
   *
   * @param {string} username
   */
  removePublicKey(username) {
    const self = this;
    _.remove(this.publicKeys, (p) => {
      self._log(util.format('Removed public key for username %s', username));
      return p.username === username;
    });
  }

  /**
   * Remove all public keys
   */
  removeAllPublicKeys() {
    this._log(util.format('Removed all public keys'));
    this.publicKeys = [];
  }

  /**
   * Add a host key. You need at least one host key before you can start the server.
   *
   * @param {string} key
   */
  addHostKey(key) {
    this._log('Added server key');
    this.hostKeys.push(key);
  }

  /**
   * Starts the SFTP server listening
   *
   * @param {number} port
   * @param {string} bindAddress
   * @param {Function} [callback]
   */
  listen(port, bindAddress, callback) {
    if(this.ssh)
      throw new Error('Already running');

    this.ssh = new ssh2.Server({
      hostKeys: this.hostKeys
    }, (client) => {
		let pubKey;
		client.on('error', (err) => {
        this.emit('client-error', { client: client, error: err });
      });
      client.on('authentication', (ctx) => {
        if(ctx.method !== 'publickey') {
        	return this.authFn(ctx);
        }

        pubKey = this._findKey(ctx.username, ctx.key);
        if(!pubKey) {
          this._log('public key not found');
          return ctx.reject(['publickey not found']);
        }

        if(ctx.signature) {
			const verifier = crypto.createVerify(ctx.sigAlgo);
			verifier.update(ctx.blob);
          if(verifier.verify(pubKey.key.publicOrig, ctx.signature)) {
            this._log('signature verified');
            return ctx.accept();
          }
          else {
            this._log('signature rejected');
            return ctx.reject();
          }
        }
        else {
          this._log('no signature present');
          return ctx.accept();
        }
      })
      .on('ready', () => {
        client.on('session', (accept, reject) => {
			const session = accept();

			pubKey = pubKey || this.defaultPubKey;

			this._log(util.format('logging on %s', pubKey.username));
          this.emit('login', { username: pubKey.username });
          session.on('sftp', (accept, reject) => {
			  const openFiles = {};
			  const openDirs = {};
			  let handleCount = 0;

			  const sftpStream = accept();
			  sftpStream.on('OPEN', (reqid, filename, flags, attrs) => {
              this._log(util.format('SFTP OPEN filename=%s flags=%d handle=%d', filename, flags, handleCount));
              if(filename.endsWith('\\') || filename.endsWith('/')) {
                filename = filename.substring(0, filename.length - 1 );
              }
				const fullname = this._mapKey(pubKey.path, filename);

				if(flags & OPEN_MODE.READ) {
				  this.storage.listObjects(fullname, (err, data) => {
                  if(err) {
                    this._logError(util.format('S3 error listing %s: %s', fullname, err));
                    return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                  }

					let f = _.find(data.Contents, { Key: fullname }); //exact filename match
                  if(!f) {
                    this._log(util.format('Key %s not found in S3 list', fullname));
                    return sftpStream.status(reqid, STATUS_CODE.NO_SUCH_FILE);
                  }

					const handle = new Buffer(4);

					this._log(util.format('Issuing handle %d', handleCount));
                  openFiles[handleCount] = { flags: flags, filename: filename, size: f.Size, fullname: fullname };
                  handle.writeUInt32BE(handleCount++, 0, true);
                  sftpStream.handle(reqid, handle);
                });
              }
              else if(flags & OPEN_MODE.WRITE) {
				  const stream = new PassThrough();

				  this._log(util.format('Issuing handle %d', handleCount));
                var handle = new Buffer(4);
                openFiles[handleCount] = { flags: flags, filename: filename, fullname: fullname, stream: stream };
				  const state = openFiles[handleCount];
				  handle.writeUInt32BE(handleCount++, 0, true);
                sftpStream.handle(reqid, handle);

				  this.storage.upload(fullname, stream, (err, data) => {
                  //Done uploading
                  delete openFiles[state.fnum];

                  if(err) {
                    this._logError(util.format('S3 error uploading %s: %s', fullname, err));
                    return sftpStream.status(state.reqid, STATUS_CODE.FAILURE);
                  }

                  this._log(util.format('Successfully uploaded %s', fullname));
                  this.emit('file-uploaded', { path: state.fullname, username: pubKey.username });
                  sftpStream.status(state.reqid, STATUS_CODE.OK);
                  this.postUploadCb(fullname);
                });
              }
              else {
                this._log(util.format('Unsupported operation'));
                return sftpStream.status(reqid, STATUS_CODE.OP_UNSUPPORTED);
              }
            }).on('READ', (reqid, handle, offset, length) => {
              if(handle.length !== 4)
                return sftpStream.status(reqid, STATUS_CODE.FAILURE);

				const handleId = handle.readUInt32BE(0, true);

				this._log(util.format('SFTP READ handle=%d offset=%d length=%d', handleId, offset, length));

				let state = openFiles[handleId];
				if(!state || !(state.flags & OPEN_MODE.READ)) {
                this._log('Invalid flags');
                return sftpStream.status(reqid, STATUS_CODE.FAILURE);
              }

              if(state.read) {
                this._log('EOF');
                return sftpStream.status(reqid, STATUS_CODE.EOF);
              }

              if(offset + length > state.size)
                length = state.size - offset;

              if(offset >= state.size || length === 0) {
                this._log('Invalid offset');
                return sftpStream.status(reqid, STATUS_CODE.FAILURE);
              }

              if(offset + length >= state.size) {
                state.read = true;
              }

              this.storage.getObject(state.fullname, `bytes=${offset}-${offset+length-1}`, (err, data) => {
                if(err || data.Body.length === 0) {
                  this._logError(util.format('S3 error getting object %s: %s', state.fullname, err));
                  return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                }

                this._log(util.format('Successfully read %s', state.fullname));
                sftpStream.data(reqid, data.Body);
              });

            }).on('WRITE', (reqid, handle, offset, data) => {
              if (handle.length !== 4)
                return sftpStream.status(reqid, STATUS_CODE.FAILURE);

				const handleId = handle.readUInt32BE(0, true);

				this._log(util.format('SFTP WRITE handle=%d offset=%d', handleId, offset));

				let state = openFiles[handleId];
				if(!state || !(state.flags & OPEN_MODE.WRITE)) {
                this._log('Invalid flags');
                return sftpStream.status(reqid, STATUS_CODE.FAILURE);
              }

              state.stream.write(new Buffer(data), (err, data) => {
                if(err) {
                  this._logError('Error writing to stream', err);
                  return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                }

                this._log('Wrote bytes to stream');
                sftpStream.status(reqid, STATUS_CODE.OK);
              });
            }).on('OPENDIR', (reqid, path) => {
              this._log(util.format('SFTP OPENDIR %s', path));
				const fullname = this._mapKey(pubKey.path, path);
				let isRoot = (path === '/');

				  this.storage.listObjects(fullname, (err, data) => {
                if(err) {
                  this._logError(util.format('S3 error listing %s: %s', fullname, err));
                  return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                }

                if(data.Contents.length === 0 && !isRoot) {
                  this._log(util.format('Key %s not found'), fullname);
                  return sftpStream.status(reqid, STATUS_CODE.NO_SUCH_FILE);
                }

				  const handle = new Buffer(4);

				  const listings = _.filter(data.Contents, (c) => {
					  let f = c.Key.substring(fullname.length);
					  if (!f.startsWith('/'))
						  f = '/' + f;
					  if (f === '/.dir')
						  return false;
					  const parts = f.split('/');
					  if (parts[0])
						  return false;
					  if (parts.length === 3 && parts[2] === '.dir') {
						  if (!parts[1])
							  return false;
						  c.Key = c.Key.substring(0, c.Key.length - 4);
						  c.IsDir = true;
						  return true;
					  }
					  return parts.length === 2;
				  });

				  this._log(util.format('Issuing handle %d', handleCount));
                openDirs[handleCount] = { fullname: fullname, listings: listings };
                handle.writeUInt32BE(handleCount++, 0, true);
                sftpStream.handle(reqid, handle);
              });
            }).on('READDIR', (reqid, handle) => {
              if (handle.length !== 4)
                return sftpStream.status(reqid, STATUS_CODE.FAILURE);

				const handleId = handle.readUInt32BE(0, true);

				this._log(util.format('SFTP READDIR handle=%d', handleId));

				let state = openDirs[handleId];
				if(!state) {
                this._log('Unknown handle');
                return sftpStream.status(reqid, STATUS_CODE.FAILURE);
              }

              if(state.read) {
                this._log('EOF');
                return sftpStream.status(reqid, STATUS_CODE.EOF);
              }

              state.read = true;

              sftpStream.name(reqid, state.listings.map((l) => {
				  let filename = l.Key.substring(state.fullname.length);
				  if(filename.startsWith('/'))
                  filename = filename.substring(1);
                if(filename.endsWith('/'))
                  filename = filename.substring(0, filename.length - 1);

				  let mode = 0;
				  mode |= constants.S_IRWXU; // read, write, execute for user
                mode |= constants.S_IRWXG; // read, write, execute for group
                mode |= constants.S_IRWXO; // read, write, execute for other

                if(l.IsDir)
                  mode |= constants.S_IFDIR;
                else
                  mode |= constants.S_IFREG;

				  const attrs = {
					  mode: mode,
					  uid: 0,
					  gid: 0,
					  size: (l.IsDir ? 1 : l.Size),
					  atime: l.LastModified,
					  mtime: l.LastModified
				  };

				  const lastModified = moment(l.LastModified);

				  this._log('Returned directory details');
                return {
                  filename: filename,
                  longname: `${l.IsDir ? 'd' : '-'}rw-rw-rw-    1 ${pubKey.username}  ${pubKey.username} ${l.Size} ${lastModified.format('MMM D')} ${moment().year() === lastModified.year() ? lastModified.format('HH:mm') : lastModified.format('YYYY')} ${_path.basename(filename)}`,
                  attrs: attrs
                };
              }));

            }).on('REALPATH', (reqid, path) => {
              this._log(util.format('SFTP REALPATH %s', path));
              if(path === '.')
                path = '/';
				let p = path;
				p = p.replace('\\\\', '/');
              p = p.replace('\\.\\', '/');
              p = p.replace('\\', '/');
              p = _path.normalize(p);
              while(p.indexOf('\\') >= 0)
                p = p.replace('\\', '/');
              if(!p.startsWith('/'))
                p = '/' + p;

				const fullname = this._mapKey(pubKey.path, path);

				this._log(util.format('listing objects under %s (%s)', fullname, p));
				  this.storage.listObjects(fullname, (err, data) => {
                if(err) {
                  this._logError(util.format('S3 error listing %s: %s', fullname, err));
                  return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                }

                this._log(util.format('%d objects found', data.Contents.length));

				  let realObj = _.find(data.Contents, (c) => c.Key === fullname || c.Key === (fullname + '/.dir'));

				  if(realObj && realObj.Key.endsWith('.dir')) {
                  this._log(util.format('%s is a directory', realObj.Key));
                  realObj.IsDir = true;
                }

                if(!realObj && (p === '/' || p === '/.')) {
                  this._log(util.format('listing empty root directory %s', p));
                  realObj = {
                    IsDir: true,
                    LastModified: new Date(),
                    Size: 0
                  };
                  p = '/';
                }

                if(!realObj) {
                  this._log(util.format('no objects found at %s', fullname));
                  return sftpStream.status(reqid, STATUS_CODE.NO_SUCH_FILE);
                }

				  const lastModified = moment(realObj.LastModified);

				  const name = [{
					  filename: p,
					  longname: `${realObj.IsDir ? 'd' :
						  '-'}rw-rw-rw-    1 ${pubKey.username}  ${pubKey.username} ${realObj.Size} ${lastModified.format(
						  'MMM D')} ${moment().year() === lastModified.year() ? lastModified.format('HH:mm') :
						  lastModified.format('YYYY')} ${_path.basename(p) || p}`
				  }];

				  this._log('Returning real name');
                sftpStream.name(reqid, name);
              });
            }).on('CLOSE', (reqid, handle) => {
              if (handle.length !== 4)
                return sftpStream.status(reqid, STATUS_CODE.FAILURE);

				const handleId = handle.readUInt32BE(0, true);

				this._log(util.format('SFTP CLOSE handle=%d', handleId));

              if(!openFiles[handleId] && !openDirs[handleId]) {
                this._log('Unknown handle');
                return sftpStream.status(reqid, STATUS_CODE.FAILURE);
              }

              if(openFiles[handleId]) {
				  const state = openFiles[handleId];

				  if (openFiles[handleId].flags & OPEN_MODE.WRITE) {
                  state.reqid = reqid;
                  state.fnum = handleId;
                  state.stream.end();
                  this._log('Stream closed');
                  return;
                }
                else {
                  this.emit('file-downloaded', { path: state.fullname, username: pubKey.username });
                  delete openFiles[handleId];
                }
              }
              else {
                delete openDirs[handleId];
              }

              this._log('Handle closed');
              sftpStream.status(reqid, STATUS_CODE.OK);
            }).on('REMOVE', (reqid, path) => {
              this._log(util.format('SFTP REMOVE %s', path));
				const fullname = this._mapKey(pubKey.path, path);

				  this.storage.deleteObject(fullname, (err, data) => {
                if(err) {
                  this._logError(util.format('S3 error deleting object %s: %s', fullname, err));
                  return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                }

                this._log('File deleted');
                this.emit('file-deleted', { path: fullname, username: pubKey.username });
                sftpStream.status(reqid, STATUS_CODE.OK);
              });
            }).on('RMDIR', (reqid, path) => {
              this._log(util.format('SFTP RMDIR %s', path));
				const fullname = this._mapKey(pubKey.path, path);

				  this.storage.listObjects(fullname, (err, data) => {
                if(err) {
                  this._logError(util.format('S3 error listing %s: %s', fullname, err));
                  return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                }

				  const keys = data.Contents.map((c) => {
					  return {
						  Key: c.Key
					  };
				  });

				  if(keys.length === 0) {
                  this._log(util.format('Key %s not found in listing', fullname));
                  return sftpStream.status(reqid, STATUS_CODE.NO_SUCH_FILE);
                }

                  this.storage.deleteObjects(keys, (err, data) => {
                  if(err) {
                    this._logError('S3 error deleting objects: %s', err);
                    return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                  }

                  this._log('Directory deleted');
                  this.emit('directory-deleted', { path: fullname, username: pubKey.username });
                  return sftpStream.status(reqid, STATUS_CODE.OK);
                });
              });
            }).on('MKDIR', (reqid, path, attrs) => {
              this._log(util.format('SFTP MKDIR %s', path));
				let procPath = _path.join(path, '.dir');
				if(procPath.endsWith('/'))
                procPath = procPath.slice(0, -1);

				const fullname = this._mapKey(pubKey.path, procPath);

				  this.storage.putObject(fullname, '', (err, data) => {
                if(err) {
                  this._logError(util.format('S3 error putting object %s: %s', fullname, err));
                  return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                }

                this._log('Directory created');
                this.emit('directory-created', { path: fullname, username: pubKey.username });
                return sftpStream.status(reqid, STATUS_CODE.OK);
              });
            }).on('RENAME', (reqid, oldPath, newPath) => {
              this._log(util.format('SFTP RENAME %s->%s', oldPath, newPath));
				const fullnameOld = this._mapKey(pubKey.path, oldPath);
				const fullnameNew = this._mapKey(pubKey.path, newPath);

				  this.storage.copyObject(fullnameNew, this.bucket+ '/' + fullnameOld, (err, data) => {
                if(err) {
                  this._logError(util.format('S3 error copying %s to %s: %s', fullnameOld, fullnameNew, err));
                  return sftpStream.status(reqid, STATUS_CODE.NO_SUCH_FILE);
                }

					  this.storage.deleteObject(fullnameOld, (err, data) => {
                  if(err) {
                    this._logError(util.format('S3 error deleting object %s: %s', fullnameOld, err));
                    return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                  }

                  this._log('File renamed');
                  this.emit('file-renamed', { path: fullnameNew, oldPath: fullnameOld, username: pubKey.username });
                  return sftpStream.status(reqid, STATUS_CODE.OK);
                });
              });
            }).on('STAT', onStat.bind(this))
              .on('LSTAT', onStat.bind(this));
            function onStat(reqid, path) {
              this._log(util.format('SFTP STAT/LSTAT %s', path));
				const fullname = this._mapKey(pubKey.path, path);

				this.storage.listObjects(fullname, (err, data) => {
                if(err) {
                  this._logError(util.format('S3 error listing %s: %s', fullname, err));
                  return sftpStream.status(reqid, STATUS_CODE.FAILURE);
                }

				  const exactMatch = _.find(data.Contents, { Key: fullname });    //exact filename match
                if(exactMatch) {
                  var mode = constants.S_IFREG;   // regular file
                  mode |= constants.S_IRWXU;      // read, write, execute for user
                  mode |= constants.S_IRWXG;      // read, write, execute for group
                  mode |= constants.S_IRWXO;      // read, write, execute for other

                  this._log('Retrieved file attrs');
                  sftpStream.attrs(reqid, {
                    mode: mode,
                    uid: 0,
                    gid: 0,
                    size: exactMatch.Size,
                    atime: exactMatch.LastModified,
                    mtime: exactMatch.LastModified
                  });
                  return;
                }

				  const directoryMatch = _.find(data.Contents, { Key: fullname + '/.dir' });    //directory match
                if(directoryMatch) {
                  var mode = constants.S_IFDIR;   // directory
                  mode |= constants.S_IRWXU;      // read, write, execute for user
                  mode |= constants.S_IRWXG;      // read, write, execute for group
                  mode |= constants.S_IRWXO;      // read, write, execute for other

                  this._log('Retrieved directory attrs');
                  sftpStream.attrs(reqid, {
                    mode: mode,
                    uid: 0,
                    gid: 0,
                    size: 1,
                    atime: directoryMatch.LastModified,
                    mtime: directoryMatch.LastModified
                  });
                  return;
                }

                //No matches
                this._log(util.format('Key %s not in listing', fullname));
                return sftpStream.status(reqid, STATUS_CODE.NO_SUCH_FILE);
              });
            }
          });
        });
      })
      .on('end', () => {

      });
    });

    this.ssh.listen(port, bindAddress, function() {
      if(callback)
        callback(port);
    });
  }

  /**
   * Stop listener
   *
   * @param {Function} cb - Callback for when stop is complete
   */
  stop(cb) {
    if(this.ssh) {
      this.ssh.close(cb);
      this.ssh = null;
    }
    else {
      process.nextTick(cb);
    }
  }

  //------------------------- Private Methods -------------------------------------

  _log() {
    if (this.loggingEnabled) {
		this.logger.info.apply(this.logger, arguments);
    }
  }

	_logError() {
		if (this.loggingEnabled) {
			this.logger.error.apply(this.logger, arguments);
		}
	}

  _findKey(username, key) {
    for (let idx = 0; idx < this.publicKeys.length; idx++) {
      if (this.publicKeys[idx]['username'] == username) {
		  const pubKey = this.publicKeys[idx];
		  if(key.algo === pubKey.key.fulltype &&
           buffersEqual(key.data, pubKey.key.public)) {
          return pubKey;
        }
      }
    }
  }

  _mapKey(path, filename) {
	  let p = filename;
	  p = p.replace('\\\\', '/');
    p = p.replace('\\.\\', '/');
    p = p.replace('\\', '/');
    p = _path.normalize(p);
    while(p.indexOf('\\') >= 0)
      p = p.replace('\\', '/');
    if(!p.startsWith('/'))
      p = '/' + p;
    return path + p;
  }
}

module.exports = SFTPServerStorage;
