import fs from "node:fs/promises";
import { ipToNumber, cidrToRange } from "../utils/iputils.js";

export class IpChecker {
	/** @type {Array<[number, number]>} */
	#ranges = [];

	/** @type {number} */
	#totalIPs = 0;

	/**
	 * Loads CIDRs from file and prepares internal range list.
	 * @param {string} filePath - Path to file with IPs or CIDRs.
	 */
	async load(filePath) {
		console.log("Loading blocked IP list...");
		const startTime = Date.now();

		const data = await fs.readFile(filePath, "utf-8");
		const cidrs = data
			.split("\n")
			.map((line) => line.trim())
			.filter(Boolean)
			.map((line) => (line.includes("/") ? line : `${line}/32`));

		this.#ranges = cidrs.map(cidrToRange);
		this.#ranges.sort((a, b) => a[0] - b[0]);

		this.#totalIPs = this.#ranges.reduce(
			(acc, [start, end]) => acc + (end - start + 1),
			0
		);

		const elapsed = (Date.now() - startTime) / 1000;
		console.log(`Total IPs: ${this.#totalIPs.toLocaleString()}`);
		console.log(`CIDR ranges loaded: ${this.#ranges.length}`);
		console.log(`Initialization time: ${elapsed.toFixed(2)}s`);
		console.log(`Memory: ${(process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2)} MB`);
	}

	/**
	 * Checks if a given IP (string or number) is blocked.
	 * @param {string|number} ip - IP address as string or number.
	 * @returns {boolean} True if blocked.
	 */
	isBlocked(ip) {
		const ipNum = typeof ip === "string" ? ipToNumber(ip) : ip;
		let left = 0;
		let right = this.#ranges.length - 1;

		while (left <= right) {
			const mid = Math.floor((left + right) / 2);
			const [start, end] = this.#ranges[mid];

			if (ipNum < start) {
				right = mid - 1;
			} else if (ipNum > end) {
				left = mid + 1;
			} else {
				return true;
			}
		}

		return false;
	}

	/**
	 * @returns {number} Total number of individual IPs covered.
	 */
	getTotalIPs() {
		return this.#totalIPs;
	}

	/**
	 * @returns {number} Number of CIDR ranges.
	 */
	getRangeCount() {
		return this.#ranges.length;
	}
}

export default IpChecker;