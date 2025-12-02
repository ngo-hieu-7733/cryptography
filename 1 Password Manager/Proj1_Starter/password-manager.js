'use strict';

/********* External Imports ********/

const {
	stringToBuffer,
	bufferToString,
	encodeBuffer,
	decodeBuffer,
	getRandomBytes,
} = require('./lib');
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64; // we can assume no password is longer than this many characters
const SALT_LENGTH = 16; // 128 bits
const IV_LENGTH = 12; // 96 bits for AES-GCM
const AES_ALGO = 'AES-GCM';
const HASH_ALGO = 'SHA-256';
const VALIDATION_TAG = 'password_validation';

/********* Implementation ********/
class Keychain {
	/**
	 * Initializes the keychain using the provided information.
	 */
	constructor(data, secrets) {
		// Public data: stored on disk (but encrypted/hashed where necessary)
		this.data = data || {
			kvs: {}, // Stores { HMAC(domain): { iv: ..., cipher: ... } }
			salt: null, // Salt for PBKDF2
			validator: '', // Validate password
		};

		// Private secrets: kept in memory only, never dumped
		this.secrets = secrets || {
			kEnc: null, // AES-GCM key for encrypting passwords
			kHmac: null, // HMAC key for indexing domains
		};
	}

	/**
	 * Helper to pad passwords to fixed length to hide actual length
	 */
	static _pad(str) {
		if (str.length > MAX_PASSWORD_LENGTH) {
			throw new Error('Password too long');
		}
		return str.padEnd(MAX_PASSWORD_LENGTH, '\0');
	}

	/**
	 * Helper to unpad passwords after decryption
	 */
	static _unpad(str) {
		// Remove trailing null bytes
		return str.replace(/\0+$/, '');
	}

	/**
	 * Helper to derive keys from password and salt
	 * Returns { kEnc, kHmac }
	 */
	static async _deriveKeys(password, salt) {
		// 1. Import password as key material
		const keyMaterial = await subtle.importKey(
			'raw',
			stringToBuffer(password),
			{ name: 'PBKDF2' },
			false,
			['deriveKey']
		);

		// 2. Derive Master Key using PBKDF2
		const masterKey = await subtle.deriveKey(
			{
				name: 'PBKDF2',
				salt: salt,
				iterations: PBKDF2_ITERATIONS,
				hash: HASH_ALGO,
			},
			keyMaterial,
			{ name: 'HMAC', hash: HASH_ALGO, length: 256 },
			true, // Extractable to derive sub-keys
			['sign']
		);

		// 3. Derive kEnc (Encryption Key) by signing a constant "enc"
		// We use HMAC as a PRF here.
		const encBytes = await subtle.sign(
			'HMAC',
			masterKey,
			stringToBuffer('encryption_key_derivation')
		);
		const kEnc = await subtle.importKey('raw', encBytes, { name: AES_ALGO }, false, [
			'encrypt',
			'decrypt',
		]);

		// 4. Derive kHmac (Indexing Key) by signing a constant "idx"
		const hmacBytes = await subtle.sign(
			'HMAC',
			masterKey,
			stringToBuffer('indexing_key_derivation')
		);
		const kHmac = await subtle.importKey(
			'raw',
			hmacBytes,
			{ name: 'HMAC', hash: HASH_ALGO },
			false,
			['sign', 'verify']
		);

		return { kEnc, kHmac };
	}

	/**
	 * Creates an empty keychain with the given password.
	 */
	static async init(password) {
		const salt = getRandomBytes(SALT_LENGTH);
		const keys = await Keychain._deriveKeys(password, salt);

		const newKeychain = new Keychain();
		newKeychain.data.salt = encodeBuffer(salt);
		newKeychain.secrets.kEnc = keys.kEnc;
		newKeychain.secrets.kHmac = keys.kHmac;

		// Calculate validator
		const validatorBuffer = await subtle.sign(
			'HMAC',
			keys.kHmac,
			stringToBuffer(VALIDATION_TAG)
		);
		newKeychain.data.validator = encodeBuffer(validatorBuffer);

		return newKeychain;
	}

	/**
	 * Loads the keychain state from the provided representation.
	 */
	static async load(password, repr, trustedDataCheck) {
		// 1. Verify Integrity if trustedDataCheck is provided
		if (trustedDataCheck !== undefined && trustedDataCheck !== null) {
			const bufferRepr = stringToBuffer(repr);
			const hashBuffer = await subtle.digest(HASH_ALGO, bufferRepr);
			const hashHex = Array.from(new Uint8Array(hashBuffer))
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');

			// Compare hex strings (or buffers)
			if (hashHex !== trustedDataCheck) {
				throw new Error('Integrity check failed: Data has been tampered with.');
			}
		}
		// TODO: check password is valid ?
		// 2. Parse JSON
		const data = JSON.parse(repr);
		if (!data.salt || !data.kvs) {
			throw new Error('Invalid keychain format');
		}

		// 3. Derive keys again using the stored salt
		const salt = decodeBuffer(data.salt);
		const keys = await Keychain._deriveKeys(password, salt);

		// 4. Check password
		const checkBuffer = await subtle.sign(
			'HMAC',
			keys.kHmac,
			stringToBuffer(VALIDATION_TAG)
		);
		const checkString = encodeBuffer(checkBuffer);

		// So sánh với validator đã lưu trong file. Nếu khác nhau nghĩa là kHmac sai => Password sai.
		if (checkString !== data.validator) {
			throw new Error('Invalid password'); // Ném lỗi theo yêu cầu đề bài
		}

		// 4. Construct object
		return new Keychain(data, {
			kEnc: keys.kEnc,
			kHmac: keys.kHmac,
		});
	}

	/**
	 * Returns a JSON serialization of the contents of the keychain.
	 */
	async dump() {
		// Serialize the data object
		const jsonRepr = JSON.stringify(this.data);

		// Compute SHA-256 hash of the JSON string for integrity
		const bufferRepr = stringToBuffer(jsonRepr);
		const hashBuffer = await subtle.digest(HASH_ALGO, bufferRepr);
		const hashHex = Array.from(new Uint8Array(hashBuffer))
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');

		return [jsonRepr, hashHex];
	}

	/**
	 * Fetches the data corresponding to the given domain.
	 */
	async get(name) {
		// 1. Calculate HMAC of the domain name (to find the key in KVS)
		const nameSig = await subtle.sign('HMAC', this.secrets.kHmac, stringToBuffer(name));
		const kvsKey = encodeBuffer(nameSig);

		// 2. Check existence
		if (!this.data.kvs[kvsKey]) {
			return null;
		}

		const entry = this.data.kvs[kvsKey];
		const iv = decodeBuffer(entry.iv);
		const ciphertext = decodeBuffer(entry.value);

		// 3. Decrypt using AES-GCM
		try {
			const paddedPlaintextBuffer = await subtle.decrypt(
				{
					name: AES_ALGO,
					iv: iv,
					additionalData: stringToBuffer(name), // Prevent Swap Attack
				},
				this.secrets.kEnc,
				ciphertext
			);

			const paddedPlaintext = bufferToString(paddedPlaintextBuffer);
			return Keychain._unpad(paddedPlaintext);
		} catch (e) {
			// Decryption failed (wrong key or tampering)
			throw new Error('Decryption failed or integrity check failed');
		}
	}

	/**
	 * Inserts the domain and associated data into the KVS.
	 */
	async set(name, value) {
		// 1. Calculate HMAC of the domain name
		const nameSig = await subtle.sign('HMAC', this.secrets.kHmac, stringToBuffer(name));
		const kvsKey = encodeBuffer(nameSig);

		// 2. Prepare data: Pad to 64 chars
		const paddedValue = Keychain._pad(value);
		const iv = getRandomBytes(IV_LENGTH);

		// 3. Encrypt using AES-GCM
		// IMPORTANT: Pass 'name' as additionalData to bind ciphertext to this domain
		const ciphertextBuffer = await subtle.encrypt(
			{
				name: AES_ALGO,
				iv: iv,
				additionalData: stringToBuffer(name),
			},
			this.secrets.kEnc,
			stringToBuffer(paddedValue)
		);

		// 4. Store in KVS
		this.data.kvs[kvsKey] = {
			iv: encodeBuffer(iv),
			value: encodeBuffer(ciphertextBuffer),
		};
	}

	/**
	 * Removes the record with name from the password manager.
	 */
	async remove(name) {
		// 1. Calculate HMAC of the domain name
		const nameSig = await subtle.sign('HMAC', this.secrets.kHmac, stringToBuffer(name));
		const kvsKey = encodeBuffer(nameSig);

		// 2. Check and remove
		if (this.data.kvs.hasOwnProperty(kvsKey)) {
			delete this.data.kvs[kvsKey];
			return true;
		}
		return false;
	}
}

module.exports = { Keychain };
